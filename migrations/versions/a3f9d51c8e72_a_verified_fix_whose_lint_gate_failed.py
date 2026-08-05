"""a verified fix whose lint gate failed

Revision ID: a3f9d51c8e72
Revises: f7c2d94ab153
Create Date: 2026-07-30

Item 067. One new value in the CHECK-constrained enum on `attempts.outcome`:
`pr-open-lint-failed`.

An attempt that clears the red gate and the green gate has proved everything this product claims —
*a test that failed against unmodified code passes with this change applied* — and then failing the
project's own lint gate used to make it `failed`: terminal, the item's one attempt spent, nothing
published but a comment. Measured on this repository, that discarded 67 model calls and ~25,000
output tokens, twice, both times for `Statement is unreachable` in a test the agent had written.

Its own value rather than reusing `pr-open`, because an artefact published under that name would
make the evidence trail say every gate passed. The trail, `hullwork status` and the pull request
body have to say the same thing, or the claim stops being falsifiable.

No data migration: no existing row can hold the new value, and the rows that would have it today are
`failed` — correctly, as the record of what happened under the old rule. Rewriting them would be
inventing an outcome for an attempt that published nothing.

No application imports, so this revision keeps describing the schema as it was when it was written.
The value tuples are literals here for the same reason.
"""

from collections.abc import Sequence

from alembic import op

revision: str = 'a3f9d51c8e72'
down_revision: str | None = 'f7c2d94ab153'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_OUTCOMES = (
    'pr-open', 'failed', 'not-reproducible', 'abandoned', 'already-fixed', 'baseline-red',
)
_NEW_OUTCOMES = (*_OLD_OUTCOMES, 'pr-open-lint-failed')


def _quoted(values: Sequence[str]) -> str:
    return ", ".join(f"'{value}'" for value in values)


def _apply(outcomes: Sequence[str]) -> None:
    """Put this value set on the constraint, whichever way the backend allows.

    **SQLite needs `foreign_keys` off around the recreate, and this revision failed in production
    without it.** A CHECK constraint cannot be altered, so the table is rebuilt; `attempt_steps` has
    a foreign key *into* `attempts`, and the drop half of the rebuild raises
    `IntegrityError: FOREIGN KEY constraint failed`, leaving `_alembic_tmp_attempts` behind and the
    receiver in a restart loop — every retry then failing on the leftover table instead of the real
    cause. Exactly what `f7c2d94ab153` and `a91f5c0d2e84` say in their own docstrings, and this
    revision was written by copying `c3e1a7f40b62`, which got away with a batch rebuild because
    nothing referenced `attempts` with rows in it yet.

    The pragma is the documented SQLite procedure for this and it only works outside a transaction —
    which is what alembic already reports on this backend (*"Will assume non-transactional DDL"*).
    `foreign_key_check` afterwards is the part that makes turning them off safe to write down: it
    asks the database whether anything was actually orphaned rather than trusting that nothing was.
    """
    if op.get_bind().dialect.name == 'sqlite':
        # **A failed rebuild leaves this behind, and the retry then fails on it instead of on the
        # real cause.** That is what happened here: the first run raised `FOREIGN KEY constraint
        # failed`, and every restart afterwards said `table _alembic_tmp_attempts already exists` —
        # so the receiver sat in a restart loop reporting a symptom of its own previous attempt.
        # Dropping it first makes a retry retry the migration rather than the wreckage.
        op.execute('DROP TABLE IF EXISTS _alembic_tmp_attempts')
        op.execute('PRAGMA foreign_keys=OFF')
        try:
            with op.batch_alter_table('attempts', recreate='always') as batch:
                batch.create_check_constraint(
                    'attempt_outcome', f"outcome IN ({_quoted(outcomes)})"
                )
        finally:
            op.execute('PRAGMA foreign_keys=ON')
        orphans = op.get_bind().exec_driver_sql('PRAGMA foreign_key_check').fetchall()
        if orphans:
            msg = f"the rebuild orphaned rows, so it is being refused: {orphans[:5]}"
            raise RuntimeError(msg)
        return

    op.drop_constraint('attempt_outcome', 'attempts', type_='check')
    op.create_check_constraint('attempt_outcome', 'attempts', f"outcome IN ({_quoted(outcomes)})")


def upgrade() -> None:
    _apply(_NEW_OUTCOMES)


def downgrade() -> None:
    # Rows carrying the new value would violate the narrower constraint. Turned back into `failed`,
    # which is what the old rule would have recorded — the artefact stays on the forge either way,
    # and a downgrade that leaves a row the schema forbids is a downgrade that does not work.
    op.execute("UPDATE attempts SET outcome = 'failed' WHERE outcome = 'pr-open-lint-failed'")
    _apply(_OLD_OUTCOMES)

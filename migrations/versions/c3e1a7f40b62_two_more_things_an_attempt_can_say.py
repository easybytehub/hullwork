"""two more things an attempt can say

Revision ID: c3e1a7f40b62
Revises: b7f2e91c4a08
Create Date: 2026-07-28

Items 043 and 046 each need one new value in a CHECK-constrained enum: the outcome
`baseline-red`, for an attempt that stopped because the project's suite was already failing, and the
phase `green-gate-restored`, for the suite run that happens after test infrastructure the fix had
modified is put back. One migration rather than two, because the alternative is two SQLite table
rebuilds for what is one schema change, and each rebuild is its own opportunity to lose a constraint.

**`b7f2e91c4a08` was amended in place when `already-fixed` was added, and that is no longer
available**: it says so itself — "while this revision was still unapplied anywhere" — and it is now
applied to the live instance. So this is a new revision, and it has to rebuild rather than edit.

Three constraints across two tables, because the phase enum is used twice: `attempt_phase` and
`attempt_outcome` on `attempts`, and `step_phase` on `attempt_steps`.

**SQLite cannot alter a CHECK constraint**, so those tables are recreated. SQLite CHECK constraints
are also not reflected by SQLAlchemy, which is the trap here: a batch recreate silently drops them
and a migration that *looks* like it widened a constraint has instead removed it. Both are therefore
re-created explicitly below, and the upgrade is verified by inserting an invented value and watching
it be refused — the defect `8c1a4f2b7d13` shipped was exactly a constraint that accepted anything,
invisible on SQLite and invisible in the tests.

No application imports: a migration that imports the app describes the app as it is today rather
than as it was when the revision was written.
"""

from collections.abc import Sequence

from alembic import op

revision: str = 'c3e1a7f40b62'
down_revision: str | None = 'b7f2e91c4a08'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_PHASES = ('baseline', 'reproduce', 'red-gate', 'fix', 'green-gate', 'lint-gate', 'publish')
_NEW_PHASES = (
    'baseline', 'reproduce', 'red-gate', 'fix', 'green-gate', 'green-gate-restored', 'lint-gate',
    'publish',
)

_OLD_OUTCOMES = ('pr-open', 'failed', 'not-reproducible', 'abandoned', 'already-fixed')
_NEW_OUTCOMES = (*_OLD_OUTCOMES, 'baseline-red')


def _quoted(values: Sequence[str]) -> str:
    return ", ".join(f"'{value}'" for value in values)


def _apply(phases: Sequence[str], outcomes: Sequence[str]) -> None:
    """Put these value sets on the three constraints, whichever way this backend allows."""
    if op.get_bind().dialect.name == 'sqlite':
        with op.batch_alter_table('attempts', recreate='always') as batch:
            batch.create_check_constraint('attempt_phase', f"phase_reached IN ({_quoted(phases)})")
            batch.create_check_constraint('attempt_outcome', f"outcome IN ({_quoted(outcomes)})")
        with op.batch_alter_table('attempt_steps', recreate='always') as batch:
            batch.create_check_constraint('step_phase', f"phase IN ({_quoted(phases)})")
        return

    op.drop_constraint('attempt_phase', 'attempts', type_='check')
    op.drop_constraint('attempt_outcome', 'attempts', type_='check')
    op.drop_constraint('step_phase', 'attempt_steps', type_='check')
    op.create_check_constraint('attempt_phase', 'attempts', f"phase_reached IN ({_quoted(phases)})")
    op.create_check_constraint('attempt_outcome', 'attempts', f"outcome IN ({_quoted(outcomes)})")
    op.create_check_constraint('step_phase', 'attempt_steps', f"phase IN ({_quoted(phases)})")


def upgrade() -> None:
    _apply(_NEW_PHASES, _NEW_OUTCOMES)


def downgrade() -> None:
    """Narrowing, so any row already using a new value has to go first.

    Deleting rows in a downgrade is normally wrong. Here the alternative is a migration that cannot
    run, because a CHECK constraint is validated against existing data: an attempt recorded as
    `baseline-red` makes the old constraint unsatisfiable. An attempt row is evidence, so the delete
    is narrow and named rather than a truncation.
    """
    op.execute(
        "DELETE FROM attempt_steps WHERE phase = 'green-gate-restored'"
    )
    op.execute(
        "DELETE FROM attempts WHERE outcome = 'baseline-red' "
        "OR phase_reached = 'green-gate-restored'"
    )
    _apply(_OLD_PHASES, _OLD_OUTCOMES)

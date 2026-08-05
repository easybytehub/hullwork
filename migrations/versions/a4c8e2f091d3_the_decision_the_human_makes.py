"""the decision the human makes

Revision ID: a4c8e2f091d3
Revises: f3b9d24c7e18
Create Date: 2026-08-03

Item 138, M13. An item gains a state for *a human refused this*, and a column for why.

**The state did not exist**, and its absence is what made review debt uncountable: a pull request a
reviewer closed without merging left its item in `pr-open` for ever, indistinguishable from one
nobody had opened yet. The milestone that claims not to create review debt has to be able to count
it.

Two changes, and the first is the awkward one. `ItemState` is a `VARCHAR` with a real `CHECK`
constraint (`models._enum`, deliberately not a native enum), so adding a value means **rewriting the
constraint**. `batch_alter_table` is how that is done on SQLite, which recreates the table, and it is
correct on Postgres too. The constraint is named explicitly here because an unnamed one cannot be
dropped by name on either.

`rejected_reason` is nullable and stays nullable on purpose: on a rejected item `NULL` means **the
reviewer did not say**, which is a different fact from any reason in the set and is counted apart.
No backfill: nothing that exists today was rejected, because nothing could be.

No application imports, so this revision keeps describing the schema as it was when it was written.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'a4c8e2f091d3'
down_revision: str | None = 'f3b9d24c7e18'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Every value the column may hold after this revision. Spelled out rather than imported: a
#: migration that reads the application's enum describes whatever the code says today, not what the
#: schema was when this ran.
_STATES = (
    "new",
    "triaged",
    "waiting-approval",
    "ready",
    "in-progress",
    "pr-open",
    "done",
    "failed",
    "not-reproducible",
    "human-only",
    "reopened",
    "rejected",
)

_WITHOUT_REJECTED = tuple(state for state in _STATES if state != "rejected")

_CONSTRAINT = "item_state"


def upgrade() -> None:
    # **Idempotent, because the first run of this migration died half way** (item 138, measured on
    # the live instance): the column landed, the table recreate failed on a foreign key, and the
    # revision was never stamped — so the retry met its own column. A migration that cannot survive
    # its own partial failure turns one outage into a manual repair.
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        # **The debris of this migration's own first failure** (item 138). `batch_alter_table`
        # recreates the table: it builds `_alembic_tmp_items`, copies the rows, then drops the
        # original — and on the live instance that drop failed on the foreign keys `attempts` holds,
        # leaving the temporary table behind and the revision unstamped. The retry then met
        # *"table _alembic_tmp_items already exists"*, which is a second failure with a different
        # message about the same wound.
        op.execute("DROP TABLE IF EXISTS _alembic_tmp_items")
    columns = {column["name"] for column in sa.inspect(bind).get_columns("items")}
    if "rejected_reason" not in columns:
        op.add_column('items', sa.Column('rejected_reason', sa.String(length=40), nullable=True))
    with op.batch_alter_table('items', schema=None) as batch:
        batch.drop_constraint(_CONSTRAINT, type_='check')
        batch.create_check_constraint(_CONSTRAINT, sa.column('state').in_(_STATES))


def downgrade() -> None:
    # A rejected item cannot survive the constraint going back, and inventing a state for it would
    # be a lie about a decision a person made. `human-only` is the honest landing place: it means
    # nothing automated should touch this, which is true of something a reviewer refused.
    op.execute("UPDATE items SET state = 'human-only' WHERE state = 'rejected'")
    with op.batch_alter_table('items', schema=None) as batch:
        batch.drop_constraint(_CONSTRAINT, type_='check')
        batch.create_check_constraint(_CONSTRAINT, sa.column('state').in_(_WITHOUT_REJECTED))
    op.drop_column('items', 'rejected_reason')

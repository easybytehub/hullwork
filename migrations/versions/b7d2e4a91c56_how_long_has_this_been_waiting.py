"""how long has this been waiting

Revision ID: b7d2e4a91c56
Revises: a4c8e2f091d3
Create Date: 2026-08-04

Item 141. An item gains a clock for *when it entered the state it is in*.

`updated_at` cannot answer that: it moves on any change at all — an occurrence counter, a permalink
arriving, a context fetch landing — so an item six days into `waiting-approval` reads as fresh the
morning its count is bumped. A board column saying *3 items* is a photograph; *3 items, oldest 6
days* is the sentence somebody acts on, and it is what makes item 138's review debt visible rather
than merely present.

**Nullable, and deliberately not backfilled.** `NULL` means *this row predates the column*. The
tempting fill is `updated_at`, and it would put a number that is not a transition time into the one
column whose whole purpose is to be trusted — the shape item 133 settled when seals written before
the cache fields began reporting *not recorded* rather than zero. Cheap here too: every item on the
live instance is `done`, so nothing anybody is waiting on loses an age it never had.

**Idempotent**, because item 138's migration went down mid-flight on a live database and the retry
met its own half-finished work. A plain `ADD COLUMN` is far less likely to, and costs one `inspect`
call to be sure.

No application imports, so this revision keeps describing the schema as it was when it was written.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'b7d2e4a91c56'
down_revision: str | None = 'a4c8e2f091d3'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = {column["name"] for column in sa.inspect(bind).get_columns("items")}
    if "state_since" not in columns:
        op.add_column("items", sa.Column("state_since", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("items", "state_since")

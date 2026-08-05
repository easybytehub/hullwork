"""the item remembers whether its lane saw the code

Revision ID: a91f5c0d2e84
Revises: d5a2c8e13f47
Create Date: 2026-07-29

Item 070, DR-0008 part 1. Half of what a lane rule reads is the culprit, and a tracker's webhook
routinely carries none — measured at 471 characters of title and link. So a lane can be chosen by
rules that were never shown the half of the error they were written about, and the reason recorded
("no lane rule matched") is true and misleading in the same breath: no rule *could* have matched.

`relane` needs to tell those decisions apart from the ones that genuinely matched nothing. It could
have string-matched the recorded reason, which is prose this column's writer does not own and which
one reworded sentence would silently turn into a no-op.

**False for every existing row, and that is the honest value rather than a convenient one.** Nobody
can say whether a decision taken before this column saw a culprit, and defaulting to True would put
every one of them permanently beyond a second look. False costs nothing: `relane` only acts once
frames actually arrive, only while nothing has happened to the item, and only when no attempt has
been spent.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'a91f5c0d2e84'
down_revision: str | None = 'd5a2c8e13f47'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # `server_default` so the NOT NULL can be added to a table that already has rows. **And it
    # stays**, which is where this differs from every neighbouring migration — they add a column
    # inside `batch_alter_table` and drop the default afterwards, so the application is the only
    # thing deciding the value.
    #
    # `items` cannot be treated that way, and the difference was found by deploying rather than by
    # reading. `batch_alter_table` on SQLite recreates the table: create a temporary copy, copy the
    # rows, **drop the original**, rename. `items` has incoming foreign keys from `attempts` and
    # `fetched_events`, so the drop fails with `FOREIGN KEY constraint failed`, leaving
    # `_alembic_tmp_items` behind — after which every restart reports `table _alembic_tmp_items
    # already exists` and the real error is invisible. The neighbouring migrations alter `attempts`,
    # which nothing references, which is why the pattern worked there.
    #
    # A plain `ADD COLUMN` is native on SQLite and touches no other table. Keeping the
    # `server_default` is the cost, and it is the cheap side of that trade: a default in two places
    # beats recreating a table that three others point at.
    op.add_column(
        'items',
        sa.Column(
            'lane_saw_code_location', sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )


def downgrade() -> None:
    # `DROP COLUMN` is native from SQLite 3.35 (2021) and, like the addition, leaves the incoming
    # foreign keys alone.
    op.drop_column('items', 'lane_saw_code_location')

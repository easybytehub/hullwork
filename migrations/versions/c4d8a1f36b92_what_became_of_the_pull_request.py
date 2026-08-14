"""What became of the pull request, asked rather than assumed. Item 253.

`opened_where` was written the moment the dispatcher opened one and never read back, so the page
said *a draft pull request is waiting for a person* about pull requests that had been merged days
before — and, worse, about ones a person had closed without merging, which displayed their explicit
"no" as work they still owed.

Measured on the live instance before this ran: two rows reading *already open*, both `merged=True`
at the forge.

`opened_state` is `NULL` for every existing row on purpose. **Not backfilled to `'open'`**: the
difference between *nobody has asked yet* and *the forge said it is open* is the whole point of the
column, and a backfill would erase it on exactly the rows that need asking first.

Revision ID: c4d8a1f36b92
Revises: b1e7c3d94f26
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "c4d8a1f36b92"
down_revision = "b1e7c3d94f26"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("upgrade_verdicts", sa.Column("opened_state", sa.String(10), nullable=True))
    op.add_column(
        "upgrade_verdicts", sa.Column("open_checked_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("upgrade_verdicts", "open_checked_at")
    op.drop_column("upgrade_verdicts", "opened_state")

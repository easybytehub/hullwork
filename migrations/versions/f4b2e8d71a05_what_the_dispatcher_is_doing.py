"""What the dispatcher is doing, on the lease. Item 242.

The instance report said *nothing in progress* while a verification built an image and ran somebody
else's suite twice, because it read `Item.state == IN_PROGRESS` and a dependency verification is not
an item. Nothing a page could infer covers the gap between two writes, and that gap is exactly the
four minutes an operator is trying to watch.

On the lease rather than in a table of its own: it is the same fact as *who is dispatching now*, and
two rows could disagree about whether one exists.

Revision ID: f4b2e8d71a05
Revises: e0a7f31c88b2
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "f4b2e8d71a05"
down_revision = "e0a7f31c88b2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("dispatcher_lease", sa.Column("doing", sa.String(length=200), nullable=True))
    op.add_column(
        "dispatcher_lease", sa.Column("doing_since", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("dispatcher_lease", "doing_since")
    op.drop_column("dispatcher_lease", "doing")

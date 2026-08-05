"""indexes for the queries the sweep runs every minute

Revision ID: 70041b8a5246
Revises: ee6d7ca69bb0
Create Date: 2026-07-27 15:13:06.584427
"""

from collections.abc import Sequence

from alembic import op

revision: str = '70041b8a5246'
down_revision: str | None = 'ee6d7ca69bb0'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Every one of the sweep's three queries was a full table scan, once a minute, for ever, on
    # tables that only grow — `deliveries` keeps every payload verbatim. Measured at 60k rows: an
    # idle sweep with nothing whatsoever to do took 264 ms and contended with live inbound writes.
    op.create_index(
        "ix_deliveries_unprocessed", "deliveries", ["processed_at", "attempts"], unique=False
    )
    op.create_index(
        "ix_items_forge_sync_pending",
        "items",
        ["forge_sync_pending", "forge_attempts", "id"],
        unique=False,
    )
    op.create_index("ix_items_forge_checked_at", "items", ["forge_checked_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_items_forge_checked_at", table_name="items")
    op.drop_index("ix_items_forge_sync_pending", table_name="items")
    op.drop_index("ix_deliveries_unprocessed", table_name="deliveries")

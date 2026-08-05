"""the full error, read from the tracker

Revision ID: 8c1a4f2b7d13
Revises: 70041b8a5246
Create Date: 2026-07-27 20:40:00.000000

Item 036. The webhook never carried a stack trace, so nothing in this database could locate a bug
in code; this is where the fetched event lands.

No application code is imported here, deliberately. Autogenerate wants to write
`hullwork.models.UtcDateTime` into the file, and a migration that imports the app breaks for the
whole history the day that class is renamed. `sa.DateTime(timezone=True)` is what that type
compiles to.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '8c1a4f2b7d13'
down_revision: str | None = '70041b8a5246'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'fetched_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('item_id', sa.Integer(), nullable=False),
        sa.Column('provider_event_id', sa.String(length=64), nullable=False),
        sa.Column('exception_type', sa.String(length=200), nullable=True),
        sa.Column('message', sa.Text(), nullable=True),
        sa.Column('culprit', sa.Text(), nullable=True),
        sa.Column('handled', sa.Boolean(), nullable=True),
        sa.Column('level', sa.String(length=20), nullable=True),
        sa.Column('frames', sa.JSON(), nullable=False),
        sa.Column('packages', sa.JSON(), nullable=False),
        sa.Column('extra', sa.JSON(), nullable=False),
        sa.Column('runtime', sa.String(length=100), nullable=True),
        sa.Column('environment', sa.String(length=100), nullable=True),
        sa.Column('release', sa.String(length=200), nullable=True),
        sa.Column('server_name', sa.String(length=200), nullable=True),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('grouping_hash', sa.String(length=128), nullable=True),
        sa.Column('fetched_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['item_id'], ['items.id']),
        sa.PrimaryKeyConstraint('id'),
        # Re-fetching an occurrence we already hold is a no-op rather than a duplicate row.
        sa.UniqueConstraint('item_id', 'provider_event_id', name='uq_fetched_event'),
    )
    op.create_index(
        op.f('ix_fetched_events_item_id'), 'fetched_events', ['item_id'], unique=False
    )

    with op.batch_alter_table('items', schema=None) as batch_op:
        # Nullable, so this applies to a table that already has rows. Null means "never asked",
        # which is exactly what is true of every existing item.
        batch_op.add_column(
            sa.Column('context_checked_at', sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(sa.Column('context_error', sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('items', schema=None) as batch_op:
        batch_op.drop_column('context_error')
        batch_op.drop_column('context_checked_at')

    op.drop_index(op.f('ix_fetched_events_item_id'), table_name='fetched_events')
    op.drop_table('fetched_events')

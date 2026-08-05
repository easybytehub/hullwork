"""an attempt can be a rehearsal

Revision ID: d5a2c8e13f47
Revises: c3e1a7f40b62
Create Date: 2026-07-28

Item 049. `hullwork work --no-publish` runs every gate and publishes nothing, and the record has to
say so: without a column for it, a rehearsal is indistinguishable from a real attempt that failed to
publish, and `consumed` would have to be computed by whoever called `finish` rather than by `finish`
itself — the second place item 042 was spent removing.

Nullable is refused. An existing row is not a rehearsal, and a NULL that has to be read as `False`
everywhere is a default hiding in the query layer.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'd5a2c8e13f47'
down_revision: str | None = 'c3e1a7f40b62'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # `server_default` so the NOT NULL can be added to a table that already has rows, and dropped
    # afterwards so the application stays the only thing that decides the value.
    with op.batch_alter_table('attempts') as batch:
        batch.add_column(
            sa.Column('rehearsal', sa.Boolean(), nullable=False, server_default=sa.false())
        )
    with op.batch_alter_table('attempts') as batch:
        batch.alter_column('rehearsal', server_default=None)


def downgrade() -> None:
    with op.batch_alter_table('attempts') as batch:
        batch.drop_column('rehearsal')

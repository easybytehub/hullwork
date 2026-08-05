"""the item remembers when the forge was last asked

Revision ID: d2de3c1b897f
Revises: 54d514f4e90f
Create Date: 2026-07-27 13:20:36.639488
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'd2de3c1b897f'
down_revision: str | None = '54d514f4e90f'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Nullable, and null means "never asked", so every existing item is due for a check on the
    # first sweep after this runs. That is what recovers the ones a human already closed while
    # nothing was watching.
    with op.batch_alter_table('items', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('forge_checked_at', sa.DateTime(timezone=True), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table('items', schema=None) as batch_op:
        batch_op.drop_column('forge_checked_at')

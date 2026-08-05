"""a delivery counts its attempts

Revision ID: ee6d7ca69bb0
Revises: d2de3c1b897f
Create Date: 2026-07-27 14:57:42.364572
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'ee6d7ca69bb0'
down_revision: str | None = 'd2de3c1b897f'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Existing rows start at zero. The ones already sealed keep `processed_at` set, so the counter
    # never selects them; the ones still pending get their full allowance, which is right — they
    # were never given a second chance under the old behaviour.
    with op.batch_alter_table('deliveries', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('attempts', sa.Integer(), nullable=False, server_default='0')
        )


def downgrade() -> None:
    with op.batch_alter_table('deliveries', schema=None) as batch_op:
        batch_op.drop_column('attempts')

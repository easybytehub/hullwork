"""an item keeps the intent to be filed

Revision ID: 54d514f4e90f
Revises: 1f83673e3596
Create Date: 2026-07-27 12:24:58.808929
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '54d514f4e90f'
down_revision: str | None = '1f83673e3596'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('items', schema=None) as batch_op:
        # server_default on the NOT NULL columns, or this cannot be applied to a table that already
        # has rows — and an upgrade that only works on an empty database is not an upgrade.
        batch_op.add_column(
            sa.Column('forge_sync_pending', sa.Boolean(), nullable=False,
                      server_default=sa.false())
        )
        batch_op.add_column(
            sa.Column('forge_attempts', sa.Integer(), nullable=False, server_default='0')
        )
        batch_op.add_column(sa.Column('forge_error', sa.Text(), nullable=True))

    # Deploying the fix is the recovery. Every item already in this database that never got its
    # issue goes back into the queue here, so nobody has to remember to run a script — and the
    # tracker that sent those errors will not send them again (GlitchTip notifies once per issue,
    # ever), which makes this the only chance they get.
    # The state literal is written out rather than imported from the application enum: a migration
    # has to keep meaning what it meant on the day it ran, whatever the code does later.
    op.execute(
        "UPDATE items SET forge_sync_pending = true "
        "WHERE forge_issue_ref IS NULL AND state <> 'done'"
    )


def downgrade() -> None:
    with op.batch_alter_table('items', schema=None) as batch_op:
        batch_op.drop_column('forge_error')
        batch_op.drop_column('forge_attempts')
        batch_op.drop_column('forge_sync_pending')

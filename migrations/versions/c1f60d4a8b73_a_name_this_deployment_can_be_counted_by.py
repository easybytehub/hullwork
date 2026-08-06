"""a name this deployment can be counted by

Revision ID: c1f60d4a8b73
Revises: b7d2e4a91c56
Create Date: 2026-08-06

Item 151. One row holding sixteen random bytes: what distinguishes forty crashes from one
installation from one crash from forty installations.

**The table is created empty and stays empty until something reports.** An upgrade must not enrol
anybody: the row is written on first use, so a deployment that never sends anything upstream never
acquires an identifier, and this migration is the whole of what an upgrade does here.

Nothing derived from the machine goes in it — not the hostname, not a MAC, not a hash of either. A
hash of a hostname is still the hostname to anybody holding a list of hostnames to try.

No application imports, so this revision keeps describing the schema as it was when it was written.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'c1f60d4a8b73'
down_revision: str | None = 'b7d2e4a91c56'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'installation',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('identifier', sa.String(length=32), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    op.drop_table('installation')

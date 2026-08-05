"""a credential that only reads

Revision ID: e5a1c73b9d20
Revises: d2f7b53c9e41
Create Date: 2026-08-02

Item 122. One row holding one hash: the token that opens the read-only page.

**No row is the default, and it is the whole security posture of this table.** The page lives on the
receiver, because the dispatcher listens on nothing and that is what lets it hold a push credential
(DR-0009) — and the receiver is the half that must be reachable by an error tracker, which on a
hosted tracker means a public address. An upgrade must therefore not *add* a page: until somebody
runs `hullwork page-token`, every path under the page prefix answers `404` like any other unknown
path, and there is nothing here to find.

The hash and not the token, exactly as `projects.webhook_secret_hash` does it, with the same
helpers: shown once at the terminal, never stored, never printed again.

No application imports, so this revision keeps describing the schema as it was when it was written.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'e5a1c73b9d20'
down_revision: str | None = 'd2f7b53c9e41'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'page_access',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    op.drop_table('page_access')

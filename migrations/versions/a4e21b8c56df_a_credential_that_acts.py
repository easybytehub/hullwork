"""a credential that acts

Revision ID: a4e21b8c56df
Revises: c1f60d4a8b73
Create Date: 2026-08-07

Item 166. Two tables: the credential that may change something, and the sessions it issues.

**Neither replaces `page_access`, and the split is the security model rather than tidiness.** The page
token is a bearer credential that lives in a URL — a saved page, a screenshot of the address bar, a
link mailed to a colleague — so it reads everything and may never spend money. `operator_key` never
appears in a URL: it is pasted into a form once, exchanged for a session, and after that only the
session cookie travels. A reader handed the read link is still safe to hand it to.

**No row is the default, and an upgrade therefore adds no buttons.** Until somebody runs
`hullwork operator-key`, the page renders what it rendered before this revision and every mutating
route answers `404` — the same answer as a wrong page token, so probing cannot even learn whether an
instance has an operator key.

Sessions are rows so that revoking is deleting. A signed cookie cannot be withdrawn without rotating
the signing key, which ends every session at once and leaves no way to end one; the morning a laptop
goes missing, that is the only lever anybody has.

`expires_at` is absolute rather than an idle timeout: an idle timeout has to be written on every
request, which turns reading the page into a write, and the receiver's sweep already contends for that
lock (`database is locked`, item 134).

No application imports, so this revision keeps describing the schema as it was when it was written.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'a4e21b8c56df'
down_revision: str | None = 'c1f60d4a8b73'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'operator_key',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('key_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'operator_session',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('csrf', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    # Looked up by hash on every request that carries the cookie, which is every render of the page
    # for a logged-in operator.
    op.create_index(
        op.f('ix_operator_session_token_hash'), 'operator_session', ['token_hash'], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f('ix_operator_session_token_hash'), table_name='operator_session')
    op.drop_table('operator_session')
    op.drop_table('operator_key')

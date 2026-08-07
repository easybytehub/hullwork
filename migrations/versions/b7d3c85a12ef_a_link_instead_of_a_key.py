"""a link instead of a key

Revision ID: b7d3c85a12ef
Revises: a4e21b8c56df
Create Date: 2026-08-07

Item 167. `operator_key` out, `sign_in_invite` in. `operator_session` is untouched.

**The authority did not change; its delivery did.** One revision earlier an operator was asked to keep
32 random bytes somewhere and paste them into a form — a password with none of a password's
affordances. `hullwork sign-in` now prints a link, opening it exchanges it for a session, and the row is
deleted in the same transaction. Single use is the security property: a link that has been opened has
already been spent, so a leaked one is worth less than a stored key would be.

**Dropping `operator_key` ends nothing that was working.** Any session it issued lives in
`operator_session` and keeps working until it expires; what disappears is the ability to issue more
from that key, which is the intended effect of replacing it. An instance upgrading through this
revision signs in again with one command.

No application imports, so this revision keeps describing the schema as it was when it was written.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'b7d3c85a12ef'
down_revision: str | None = 'a4e21b8c56df'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'sign_in_invite',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_sign_in_invite_token_hash'), 'sign_in_invite', ['token_hash'], unique=False
    )
    op.drop_table('operator_key')


def downgrade() -> None:
    op.create_table(
        'operator_key',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('key_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.drop_index(op.f('ix_sign_in_invite_token_hash'), table_name='sign_in_invite')
    op.drop_table('sign_in_invite')

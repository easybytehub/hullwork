"""a password the browser can fill

Revision ID: c8f4a1d63b27
Revises: b7d3c85a12ef
Create Date: 2026-08-07

Item 168. `sign_in_invite` out, `operator_password` in. `operator_session` keeps its shape.

**Third design in three revisions, and the first two were secure and unusable.** A stored key had to be
pasted into a form; a one-time link had to be fetched from the host every twelve hours. The operator
counted the second one out loud: open the page, ssh, run a command, copy a link, open it, come back,
reload. What this stores is a password, because a browser's password manager fills one in — one visit to
the host, ever.

`hashlib.scrypt`, from the standard library, at `n=2**14, r=8, p=1` — 37 ms per attempt on the
deployment host. The parameters live on the row rather than in the code so raising them later keeps
existing passwords verifiable instead of locking their owners out. `failures` and `locked_until` are on
the same row because an instance has one operator: a lockout is about the credential, and a per-address
counter is defeated by changing address, which is free.

**Sessions issued by the old mechanism keep working** until they expire; what disappears is the ability
to issue more. An instance upgrading through this revision sets a password once.

No application imports, so this revision keeps describing the schema as it was when it was written.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'c8f4a1d63b27'
down_revision: str | None = 'b7d3c85a12ef'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'operator_password',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('salt', sa.String(length=32), nullable=False),
        sa.Column('key', sa.String(length=64), nullable=False),
        sa.Column('n', sa.Integer(), nullable=False),
        sa.Column('r', sa.Integer(), nullable=False),
        sa.Column('p', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('failures', sa.Integer(), nullable=False),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.drop_index(op.f('ix_sign_in_invite_token_hash'), table_name='sign_in_invite')
    op.drop_table('sign_in_invite')


def downgrade() -> None:
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
    op.drop_table('operator_password')

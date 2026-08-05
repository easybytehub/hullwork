"""the dispatcher holds a lease

Revision ID: b7c3e91a05df
Revises: a91f5c0d2e84
Create Date: 2026-07-29

Item 075, DR-0009. The clock moves into the process that writes code, because that is the only place it
can live: outside is refused by the operator, and inside the receiver is refused by `main.lifespan`.

One row, renewed every turn, answering three questions that turned out to be one. May I dispatch —
`_SWEEP_LOCK` is in-process and does not cover a second process. Is the dispatcher alive — the renewal
*is* the heartbeat, so nothing can disagree with the lock about who is running. Did the previous one
die — an expired lease is the evidence that lets the next start release items claimed by a corpse.

A **lease** rather than a lock, and the distinction is why this is a table and not a file: a lock has
to be released to be correct, and a process that is killed releases nothing. This expires on its own,
which is the only mutual exclusion that survives `docker kill` without a supervisor cleaning up after
it — and a supervisor is the dependency DR-0009 exists to remove.

`create_table` rather than `add_column`, so none of migration `a91f5c0d2e84`'s trouble applies: nothing
references this table and nothing is recreated.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'b7c3e91a05df'
down_revision: str | None = 'a91f5c0d2e84'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'dispatcher_lease',
        sa.Column('id', sa.Integer(), nullable=False),
        # 64 characters for an opaque identifier of one run. Never derived from the host or the user:
        # this value is written to the database and to logs, and a lease is not a place to disclose
        # who is running Hullwork.
        sa.Column('holder', sa.String(length=64), nullable=False),
        sa.Column('acquired_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('renewed_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    op.drop_table('dispatcher_lease')

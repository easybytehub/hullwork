"""the lease says whether the dispatcher reports its own errors

Revision ID: d2f7b53c9e41
Revises: c81d4a6e2b93
Create Date: 2026-08-02

Item 110's one piece of buildable work, and it exists because of where the decision is made.

`/ready` says whether the **receiver**'s error reporting is on, because that process answers the
request. Nobody could say it for the **dispatcher**: it is a second program (DR-0009) that listens
on nothing, so the only thing it shares with `status` is this database. Item 090 built the
reporting; whether it is actually on was knowable by reading the container's first line of output
and in no other way — which is the thing this product exists to stop people doing.

One nullable `BOOLEAN`, written beside the holder when a dispatcher takes the lease.

**Nullable, and it is not laziness.** A lease taken by a build older than this column has no answer,
and `NULL` says *"not recorded"* — which is a third thing, distinct from `off`. Defaulting it to
`false` would report a capability as switched off on the strength of nothing, and item 105 was
closed for exactly that: a trail that cannot tell an absent measurement from a measured zero.

No data migration, for the same reason.

No application imports, so this revision keeps describing the schema as it was when it was written.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'd2f7b53c9e41'
down_revision: str | None = 'c81d4a6e2b93'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('dispatcher_lease', sa.Column('error_reporting', sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column('dispatcher_lease', 'error_reporting')

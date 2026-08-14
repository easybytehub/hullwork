"""The token is the fact, not the account.

`d5a7c31f9e04` added `ingest_can_push`, and item 228 filled it from `PushCapability.can_push` — which
is **the account's** access to the repository, not the token's. `credentials.py` says so in a
docstring written after measuring exactly this: *a token scoped to reads and issues is refused
regardless — measured on the live instance, where this flag fired for both projects while
`POST /branches` came back `403 … scope(s): [write:repository]`*.

So the first thing the new clock did was record `True` for a correctly configured project, and the
page was one deploy from painting a permanent red *its ingest credential CAN push, which DR-0009
forbids* over an instance where the credential cannot. That is the permanently-on signal item 073
deleted a whole check for, rebuilt by hand three items later.

The column carries `token_can_push` now, and its name says which of the two questions it answers.
Every existing value is dropped rather than migrated: they answer the other question.

No application imports, so this revision keeps describing the schema as it was when it was written.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b2e9f47a10c3"
down_revision: str | None = "d5a7c31f9e04"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_column("projects", "ingest_can_push")
    op.add_column("projects", sa.Column("ingest_token_can_push", sa.Boolean(), nullable=True))
    op.execute(sa.text("UPDATE projects SET ingest_checked_at = NULL"))


def downgrade() -> None:
    op.drop_column("projects", "ingest_token_can_push")
    op.add_column("projects", sa.Column("ingest_can_push", sa.Boolean(), nullable=True))

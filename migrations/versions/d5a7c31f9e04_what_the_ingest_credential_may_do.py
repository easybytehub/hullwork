"""What the ingest credential may do, and when that was measured.

Two nullable columns on `projects`, for the answer to the question the whole two-program split
exists to guarantee: **can the credential this instance ingests with also push code?** DR-0009
forbids it, `credentials.audit` measures it, and until item 228 the page read the answer out of a
key inside the manifest JSON that **nothing ever wrote** — so it said *not asked yet* for the life
of every instance, and running the command it told you to run would not have changed that.

A column rather than a key in the manifest, because the manifest is the project's own document
adopted verbatim (DR-0012) and instance-measured facts have no business inside it.

**Nullable, and the reason is the same one it always is.** `NULL` is *not measured*, which is a
third answer and never a `False`: reporting *cannot push* for a project nobody has asked about is
the mistake this project has now made in three different places.

`checked_at` alongside, because an answer with no timestamp is the permanently-on signal item 073
deleted a whole check for. A verdict from three weeks ago is a different thing from one from ten
minutes ago, and only the row can say which it is.

No application imports, so this revision keeps describing the schema as it was when it was written.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d5a7c31f9e04"
down_revision: str | None = "c8f4a1d63b27"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("projects", sa.Column("ingest_can_push", sa.Boolean(), nullable=True))
    op.add_column("projects", sa.Column("ingest_checked_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("projects", "ingest_checked_at")
    op.drop_column("projects", "ingest_can_push")

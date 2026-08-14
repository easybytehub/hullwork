"""What is published against what you pin, and when that was asked.

DR-0024, accepted 2026-08-11: the receiver may fetch the lock files it can already read, ask OSV on
its own clock, and keep the answer — so the half of the product that needs no model, no write
credential and no Docker stops being invisible from a browser.

One row per project, overwritten. **`asked` and `taken_at` are the operator's two conditions on
accepting it**: a report with no timestamp is a claim about a moment presented as a standing fact,
and an advisory list that silently reads empty when the network was down says *you are fine* on no
evidence at all.

No application imports, so this revision keeps describing the schema as it was when it was written.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a91c4e75d203"
down_revision: str | None = "b2e9f47a10c3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "dependency_reports",
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("taken_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("asked", sa.Boolean(), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("pinned", sa.Integer(), nullable=False),
        sa.Column("findings", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.PrimaryKeyConstraint("project_id"),
    )


def downgrade() -> None:
    op.drop_table("dependency_reports")

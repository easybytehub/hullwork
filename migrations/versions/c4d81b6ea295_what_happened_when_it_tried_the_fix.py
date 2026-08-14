"""What happened when it tried the fix.

DR-0026, accepted 2026-08-12: the dispatcher may verify an upgrade on its own clock and may not open
one. This is where the verdict goes.

One row per `(project, package, was, to)`, overwritten: *does this upgrade hold today* is one
question, and yesterday's answer about the same pair is the same fact gone stale rather than a
second one.

`was` is stored because a verdict about a version that is no longer pinned reads as current and is
not — the page compares it against the report before showing anything.

No application imports, so this revision keeps describing the schema as it was when it was written.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c4d81b6ea295"
down_revision: str | None = "a91c4e75d203"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "upgrade_verdicts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("package", sa.String(length=200), nullable=False),
        sa.Column("was", sa.String(length=100), nullable=False),
        sa.Column("to", sa.String(length=100), nullable=False),
        sa.Column("outcome", sa.String(length=30), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("tried_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "package", "was", "to", name="uq_upgrade_verdict"),
    )
    op.create_index(
        op.f("ix_upgrade_verdicts_project_id"), "upgrade_verdicts", ["project_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_upgrade_verdicts_project_id"), table_name="upgrade_verdicts")
    op.drop_table("upgrade_verdicts")

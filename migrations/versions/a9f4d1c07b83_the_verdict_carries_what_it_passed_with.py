"""The verdict carries what it passed with, and whether somebody asked for it. Item 245.

`verify_next` produced an `Answer` holding the dependency files as the passing run saw them, wrote
six columns and dropped the rest. So a clean verdict could be read and never acted on: opening a
pull request needs those exact files — a lock regenerated a second time can differ, and publishing
files the suite did not pass against is the defect item 045 is named after — and the sha they were
verified at, which is what roots the branch.

Five columns rather than a table: it is the same row's business. Three of them are the request that
DR-0026 always intended (*open stays a button somebody presses*) and never had anywhere to live —
the receiver cannot open anything, so the page writes an intention here and the dispatcher, which
holds the code credential, reads it.

`artefact` is text keyed by path, not bytes: every dependency file a resolver writes is text, and one
that is not stores no artefact rather than a base64 blob nobody can read in a database browser.

Revision ID: a9f4d1c07b83
Revises: f4b2e8d71a05
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "a9f4d1c07b83"
down_revision = "f4b2e8d71a05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("upgrade_verdicts", sa.Column("artefact", sa.JSON(), nullable=True))
    op.add_column("upgrade_verdicts", sa.Column("base_sha", sa.String(length=64), nullable=True))
    op.add_column(
        "upgrade_verdicts",
        sa.Column("asked_to_open_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("upgrade_verdicts", sa.Column("opened_where", sa.Text(), nullable=True))
    op.add_column("upgrade_verdicts", sa.Column("open_note", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("upgrade_verdicts", "open_note")
    op.drop_column("upgrade_verdicts", "opened_where")
    op.drop_column("upgrade_verdicts", "asked_to_open_at")
    op.drop_column("upgrade_verdicts", "base_sha")
    op.drop_column("upgrade_verdicts", "artefact")

"""does the fix hold: the merge commit, and the watch that reads it

Revision ID: b8e3c07d5f14
Revises: a3f9d51c8e72
Create Date: 2026-07-30

M9, DR-0005's role 6. Four columns, no data migration: absence means "not asked yet", which is true of
every row that exists when this runs.

- `attempts.merge_commit`, `attempts.merged_at` — what the merge produced, and when. Written by the
  recurrence watch after asking the forge, never at publish time: Hullwork does not merge, so at publish
  time there is nothing to record and a guess would be worse than a null.
- `items.merge_checked_at` — the watch's backoff. A poll with no timestamp either asks every pass or
  never asks again, and both were measured wrong in `fetch_context` (item 083).
- `items.recurrence_note` — the verdict as a sentence, kept rather than derived. The reason a
  recurrence was *not* counted ("the release predates the merge", "the tracker reports a version rather
  than a commit") is the part an operator disagrees with, and it cannot be recomputed once the tracker
  has moved on.
- `items.recurrence_verdict` — the same verdict as a value, because the note is for a person and the
  number is for a machine. Deriving it from the item's state would be guessing: `reopened` is also what
  a returning error produces through `dedup.resolve`.

**`op.add_column`, never `batch_alter_table`.** Both tables have incoming foreign keys — `attempts`
from `attempt_steps`, `items` from `attempts` and `fetched_events` — and on SQLite a batch rebuild
drops the table, which fails with `FOREIGN KEY constraint failed` and leaves `_alembic_tmp_*` behind.
That is not a prediction: `a3f9d51c8e72` did exactly that on the live instance hours ago, put the
receiver in a restart loop, and had to be fixed with `PRAGMA foreign_keys=OFF` plus a
`foreign_key_check`. Adding a column needs none of it, which is why every column-adding revision here
says so (`a91f5c0d2e84`, `e4b8a1c72d90`, `f7c2d94ab153`).

No application imports, so this keeps describing the schema as it was when it was written.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'b8e3c07d5f14'
down_revision: str | None = 'a3f9d51c8e72'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('attempts', sa.Column('merge_commit', sa.String(length=64), nullable=True))
    op.add_column('attempts', sa.Column('merged_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('items', sa.Column('merge_checked_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('items', sa.Column('recurrence_note', sa.Text(), nullable=True))
    op.add_column('items', sa.Column('recurrence_verdict', sa.String(length=20), nullable=True))


def downgrade() -> None:
    # Native from SQLite 3.35, and it leaves the incoming foreign keys alone.
    op.drop_column('items', 'recurrence_verdict')
    op.drop_column('items', 'recurrence_note')
    op.drop_column('items', 'merge_checked_at')
    op.drop_column('attempts', 'merged_at')
    op.drop_column('attempts', 'merge_commit')

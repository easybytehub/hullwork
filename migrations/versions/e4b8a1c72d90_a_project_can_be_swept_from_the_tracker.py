"""a project can be swept from the tracker

Revision ID: e4b8a1c72d90
Revises: b7c3e91a05df
Create Date: 2026-07-30

DR-0011, item 080. The tracker notifies once per issue for the issue's whole life, so only the first
appearance of a new signature ever arrives — measured on the live instance: **six of fifteen
unresolved issues had never entered Hullwork**, including the one with the most events by a factor of
nineteen, which turned out to be a defect in Hullwork's own write path.

Two columns:

* `tracker_project` — what this project is called in the tracker. Instance configuration, not
  manifest: a repository naming somebody else's tracker project would be reading errors it does not
  own. It cannot be discovered either, because the least-privilege token is refused
  `/api/0/organizations/` and `/api/0/projects/` (measured, 403). `NULL` means "not swept".
* `tracker_swept_until` — how far the sweep has read, by the tracker's own `lastSeen`. `NULL` means
  **never swept**, which is deliberately different from "swept and found nothing": the first sweep of
  a project with a backlog would file one forge issue per open issue, and three hundred on somebody's
  first afternoon is DR-0006's adoption failure from the other direction. So the first pass is an
  explicit act with its count shown first.

  A mark on last activity rather than a page cursor, because the provider's `Link` header is unusable
  — it arrives wrapped in Python set syntax on every list response.

**`add_column`, not `batch_alter_table`**, and the reason is the same one item 070's migration
records after finding it by deploying: on SQLite, `batch_alter_table` recreates the table — copy,
**drop the original**, rename — and `projects` has incoming foreign keys from `items`, `deliveries`,
`events` and `fetched_events`. The drop fails with `FOREIGN KEY constraint failed`, leaves
`_alembic_tmp_projects` behind, and every restart afterwards reports `table _alembic_tmp_projects
already exists` while the real error is invisible. A plain `ADD COLUMN` is native on SQLite and
touches no other table.

Both nullable, so no `server_default` is needed and none is added: absence is the meaningful value in
each case, and `NULL` says it without a default in two places.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'e4b8a1c72d90'
down_revision: str | None = 'b7c3e91a05df'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('projects', sa.Column('tracker_project', sa.String(length=200), nullable=True))
    op.add_column(
        'projects', sa.Column('tracker_swept_until', sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    # Native from SQLite 3.35 (2021), and it leaves the incoming foreign keys alone for the same
    # reason the addition does.
    op.drop_column('projects', 'tracker_swept_until')
    op.drop_column('projects', 'tracker_project')

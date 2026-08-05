"""the item carries its tracker reference

Revision ID: f7c2d94ab153
Revises: e4b8a1c72d90
Create Date: 2026-07-30

Item 086. The permalink used to live only on `events` rows, joined back by `(project_id,
fingerprint)` — fine while the webhook was the only way in, because processing a delivery always
wrote an event. The inventory sweep (item 080) writes no events, so its items had no permalink
anywhere `_permalink_for` could see: enrichment silently never ran for them, and the first real
dogfood attempt was dispatched with a brief carrying the issue title and nothing else. The agent
went looking for the bug with less information than the tracker had been holding all along.

Nullable, no default: absence means "no tracker reference known", which is true of it. Existing rows
are backfilled lazily by `dedup.resolve` the next time a fact arrives for them, and read through the
events fallback until then — nothing needs a data migration.

`add_column`, never `batch_alter_table`: `items` has incoming foreign keys from `attempts` and
`fetched_events`, and on SQLite a batch alter recreates the table — the drop fails with `FOREIGN KEY
constraint failed` and leaves `_alembic_tmp_items` behind. Same reasoning, same shape, as
`a91f5c0d2e84` and `e4b8a1c72d90`, both of which record finding that by deploying.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'f7c2d94ab153'
down_revision: str | None = 'e4b8a1c72d90'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('items', sa.Column('permalink', sa.String(length=500), nullable=True))


def downgrade() -> None:
    # Native from SQLite 3.35, and it leaves the incoming foreign keys alone.
    op.drop_column('items', 'permalink')

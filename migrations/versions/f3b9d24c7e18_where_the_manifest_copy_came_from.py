"""where the manifest copy came from

Revision ID: f3b9d24c7e18
Revises: e5a1c73b9d20
Create Date: 2026-08-02

DR-0012, built as item 128. Connecting a project stops requiring a commit to that project's
repository — as a named mode, never as the default.

One nullable column, because `refresh` now behaves differently depending on the answer and because a
reader of `projects list` deserves to know which projects their own repository does not declare.

**Nullable, and the reason is the same one it always is.** Every project registered before this
column existed came from a repository, and writing `'repository'` for them would be inferring it
rather than knowing it. `NULL` says *not recorded*: it is a third answer, and `refresh` treats it as
the old behaviour — go and read the forge — which is exactly what those projects have always done.

No application imports, so this revision keeps describing the schema as it was when it was written.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'f3b9d24c7e18'
down_revision: str | None = 'e5a1c73b9d20'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('projects', sa.Column('manifest_origin', sa.String(length=20), nullable=True))


def downgrade() -> None:
    op.drop_column('projects', 'manifest_origin')

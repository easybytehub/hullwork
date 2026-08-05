"""a step says what environment it ran in

Revision ID: c81d4a6e2b93
Revises: b8e3c07d5f14
Create Date: 2026-08-01

Item 106, part 6 — the criterion item 099 closed owing.

Item 099 fixed *which* environment a phase is given: five variables that used to sit inside the
namespace the watched project validates, so a project with a strict settings loader failed its own
suite whenever Hullwork's agent ran it. The fix is right by construction. What a reviewer could not
do afterwards is **see** it: the trail records each command, its exit code and its output, and never
the environment it ran under — so "the agent's phase and the gate ran in different environments",
the whole shape of that defect, was invisible in the one artefact a reviewer reads.

One nullable `TEXT` column holding a JSON object. Nullable rather than defaulted to `'{}'` because
`{}` is a real answer here and means *"nothing was added to this command's environment"* — which is
true of every gate and is the fact worth seeing next to a phase where it is not. A row written
before this revision knows neither, and `NULL` says that instead of claiming the gate's answer.

No data migration for the same reason: back-filling `'{}'` would assert about attempts that ran
before anything recorded this, and an evidence trail that invents evidence is worth less than one
with a gap in it.

No application imports, so this revision keeps describing the schema as it was when it was written.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'c81d4a6e2b93'
down_revision: str | None = 'b8e3c07d5f14'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # A plain `ADD COLUMN`, which SQLite supports without the table rebuild that `a3f9d51c8e72`
    # needed for a CHECK constraint — so none of that revision's foreign-key ceremony applies here.
    op.add_column('attempt_steps', sa.Column('environment', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('attempt_steps', 'environment')

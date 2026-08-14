"""The emptied artefacts read as empty from SQL too. Item 245.

`artefact` was a plain `JSON` column, so assigning `None` wrote the JSON text `null` rather than SQL
`NULL`. Four bytes — the 400 KB really is released, and the row reads `None` in Python — but
`WHERE artefact IS NOT NULL` counts it, and `forget_stale` filters on exactly that predicate.

Measured the minute it mattered: the check run just after the first pull request was opened reported
**two** artefacts where the database held one, because the one that had just been handed to the forge
was still matching. A count that quietly disagrees with what is there is the failure this repository
spends its items on, so the column now declares `none_as_null` and the rows written before it are
normalised here.

Rewritten rather than left: a predicate that is right for new rows and wrong for old ones is worse
than one that is wrong everywhere, because nothing tells you which half you are reading.

Revision ID: b1e7c3d94f26
Revises: a9f4d1c07b83
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "b1e7c3d94f26"
down_revision = "a9f4d1c07b83"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # `'null'` is the only JSON text that means *nothing kept*; a real artefact is an object.
    op.execute(
        sa.text("UPDATE upgrade_verdicts SET artefact = NULL WHERE artefact = 'null'")
    )


def downgrade() -> None:
    # **Nothing.** The two states mean the same thing to every reader of this column, and writing
    # `'null'` back would restore a distinction whose only effect was a wrong count.
    pass

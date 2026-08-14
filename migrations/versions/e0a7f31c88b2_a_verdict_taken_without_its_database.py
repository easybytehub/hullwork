"""A verdict taken without the database the project declared. Item 238.

`upgrades.verify_one` built its sandbox without the services the manifest asks for, so any project
declaring `postgres-16` ran its suite against nothing listening on 5432 and was recorded
`already-red`. That verdict is DR-0026's honest one — *your suite was failing before anything was
touched, so no claim can be made either way* — and here it was **the truth about the wrong thing**:
the suite was not failing, it was never given what it asked for.

Eleven of them on the operator's own instance, and item 234 then stopped the queue on the most
recent one, so nothing would have re-asked them without this.

**Deleted rather than corrected**, because there is nothing to correct them to: the question was
never asked. A row that is gone is re-asked on the next idle turn, which is exactly the behaviour
wanted. And an `already-red` that was genuine — a project whose suite really is failing — costs one
verification to say so again.

Revision ID: e0a7f31c88b2
Revises: c4d81b6ea295
"""

from __future__ import annotations

from alembic import op

revision = "e0a7f31c88b2"
down_revision = "c4d81b6ea295"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DELETE FROM upgrade_verdicts WHERE outcome = 'already-red'")


def downgrade() -> None:
    """Nothing to put back. The rows said a thing that was not measured, and re-taking them is
    what the dispatcher does on its own clock."""

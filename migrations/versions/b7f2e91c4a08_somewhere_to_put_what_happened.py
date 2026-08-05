"""somewhere to put what happened

Revision ID: b7f2e91c4a08
Revises: 8c1a4f2b7d13
Create Date: 2026-07-27 21:40:00.000000

Item 038. Four tables existed and none of them could hold an agent attempt, while items 025, 027
and 028 all assumed one could.

No application code is imported: `sa.DateTime(timezone=True)` is what `UtcDateTime` compiles to,
and a migration that imports the app breaks the whole history the day that class is renamed.

`create_constraint=True` on every enum, and it is not decoration. It has defaulted to False since
SQLAlchemy 1.4, so without it the column accepts any string at all and the type is documentation
rather than a rule — the trap `models._enum` was written to avoid. The first draft of this file
omitted it, and the omission was invisible until the constraints were counted on a real Postgres.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'b7f2e91c4a08'
down_revision: str | None = '8c1a4f2b7d13'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PHASES = ('baseline', 'reproduce', 'red-gate', 'fix', 'green-gate', 'lint-gate', 'publish')
_OUTCOMES = ('pr-open', 'failed', 'not-reproducible', 'abandoned', 'already-fixed')
# `already-fixed` was added by item 039 while this revision was still unapplied anywhere.
# Amended in place rather than chained: a migration to correct a migration that has never
# run is history nobody needs, and the constraint has to list every value the model allows
# or Postgres refuses the row.


def upgrade() -> None:
    op.create_table(
        'attempts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('item_id', sa.Integer(), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            'phase_reached',
            sa.Enum(*_PHASES, name='attempt_phase', native_enum=False, create_constraint=True, length=32),
            nullable=False,
        ),
        sa.Column(
            'outcome',
            sa.Enum(*_OUTCOMES, name='attempt_outcome', native_enum=False, create_constraint=True, length=32),
            nullable=True,
        ),
        sa.Column('consumed', sa.Boolean(), nullable=False),
        sa.Column('not_consumed_reason', sa.Text(), nullable=True),
        sa.Column('base_sha', sa.String(length=64), nullable=True),
        sa.Column('production_ref', sa.String(length=200), nullable=True),
        sa.Column('branch', sa.String(length=200), nullable=True),
        sa.Column('pull_request_ref', sa.String(length=100), nullable=True),
        sa.Column('image_tag', sa.String(length=200), nullable=True),
        sa.Column('seal', sa.JSON(), nullable=False),
        sa.Column('error', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['item_id'], ['items.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_attempts_item_id'), 'attempts', ['item_id'], unique=False)

    op.create_table(
        'attempt_steps',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('attempt_id', sa.Integer(), nullable=False),
        sa.Column('ordinal', sa.Integer(), nullable=False),
        sa.Column(
            'phase',
            sa.Enum(*_PHASES, name='step_phase', native_enum=False, create_constraint=True, length=32),
            nullable=False,
        ),
        sa.Column('command', sa.Text(), nullable=False),
        sa.Column('exit_code', sa.Integer(), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('output', sa.Text(), nullable=False),
        sa.Column('output_truncated', sa.Boolean(), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['attempt_id'], ['attempts.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('attempt_id', 'ordinal', name='uq_attempt_step'),
    )
    op.create_index(
        op.f('ix_attempt_steps_attempt_id'), 'attempt_steps', ['attempt_id'], unique=False
    )

    with op.batch_alter_table('events', schema=None) as batch_op:
        # True for every row already here: on the provider we recommend, no delivery has ever
        # carried a timestamp, so every stored time is when we received it. Defaulting to true is
        # therefore not a guess — it is what the existing data means.
        batch_op.add_column(
            sa.Column(
                'timestamps_are_receipt_time',
                sa.Boolean(),
                nullable=False,
                server_default=sa.true(),
            )
        )


def downgrade() -> None:
    with op.batch_alter_table('events', schema=None) as batch_op:
        batch_op.drop_column('timestamps_are_receipt_time')

    op.drop_index(op.f('ix_attempt_steps_attempt_id'), table_name='attempt_steps')
    op.drop_table('attempt_steps')
    op.drop_index(op.f('ix_attempts_item_id'), table_name='attempts')
    op.drop_table('attempts')

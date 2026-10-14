"""add triage_annotations table for the phase-2 triage agent

Revision ID: c3d8e1f4a7b2
Revises: f7c9a2b4e1d3
Create Date: 2026-10-14 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c3d8e1f4a7b2'
down_revision: Union[str, Sequence[str], None] = 'f7c9a2b4e1d3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'triage_annotations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('alert_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('mode', sa.String(length=20), nullable=True),
        sa.Column('verdict', sa.String(length=30), nullable=True),
        sa.Column('model_verdict', sa.String(length=30), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('recommendation', sa.String(length=30), nullable=True),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('policy_notes', sa.JSON(), nullable=True),
        sa.Column('model', sa.String(length=100), nullable=True),
        sa.Column('cost_usd', sa.Float(), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_triage_annotations_id'), 'triage_annotations', ['id'], unique=False)
    op.create_index(op.f('ix_triage_annotations_alert_id'), 'triage_annotations', ['alert_id'], unique=False)
    op.create_index(op.f('ix_triage_annotations_created_at'), 'triage_annotations', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_triage_annotations_created_at'), table_name='triage_annotations')
    op.drop_index(op.f('ix_triage_annotations_alert_id'), table_name='triage_annotations')
    op.drop_index(op.f('ix_triage_annotations_id'), table_name='triage_annotations')
    op.drop_table('triage_annotations')

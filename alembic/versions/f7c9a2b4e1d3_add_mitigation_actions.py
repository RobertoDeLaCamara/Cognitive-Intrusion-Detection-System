"""add mitigation_actions table for the guardian auto-response module

Revision ID: f7c9a2b4e1d3
Revises: a1b2c3d4e5f6
Create Date: 2026-07-04 11:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f7c9a2b4e1d3'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'mitigation_actions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('src_ip', sa.String(length=45), nullable=True),
        sa.Column('action_type', sa.String(length=50), nullable=True),
        sa.Column('backend', sa.String(length=50), nullable=True),
        sa.Column('status', sa.Enum('PENDING', 'CONFIRMED', 'UNDONE', 'EXPIRED', name='mitigationstatus'), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('alert_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_mitigation_actions_id'), 'mitigation_actions', ['id'], unique=False)
    op.create_index(op.f('ix_mitigation_actions_src_ip'), 'mitigation_actions', ['src_ip'], unique=False)
    op.create_index(op.f('ix_mitigation_actions_expires_at'), 'mitigation_actions', ['expires_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_mitigation_actions_expires_at'), table_name='mitigation_actions')
    op.drop_index(op.f('ix_mitigation_actions_src_ip'), table_name='mitigation_actions')
    op.drop_index(op.f('ix_mitigation_actions_id'), table_name='mitigation_actions')
    op.drop_table('mitigation_actions')
    sa.Enum(name='mitigationstatus').drop(op.get_bind(), checkfirst=True)

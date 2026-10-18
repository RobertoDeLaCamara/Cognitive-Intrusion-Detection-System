"""add host_profiles for the asset inventory

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-10-18 11:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f6a7b8c9d0e1'
down_revision: Union[str, Sequence[str], None] = 'e5f6a7b8c9d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'host_profiles',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('ip', sa.String(length=45), nullable=False),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.Column('flows_out', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('flows_in', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('listen_ports', sa.JSON(), nullable=True),
        sa.Column('out_ports', sa.JSON(), nullable=True),
        sa.Column('peers', sa.JSON(), nullable=True),
        sa.Column('classification', sa.String(length=20), nullable=False, server_default='unknown'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_host_profiles_id', 'host_profiles', ['id'])
    op.create_index('ix_host_profiles_ip', 'host_profiles', ['ip'], unique=True)
    op.create_index('ix_host_profiles_last_seen', 'host_profiles', ['last_seen'])
    op.create_index('ix_host_profiles_classification', 'host_profiles', ['classification'])


def downgrade() -> None:
    op.drop_index('ix_host_profiles_classification', table_name='host_profiles')
    op.drop_index('ix_host_profiles_last_seen', table_name='host_profiles')
    op.drop_index('ix_host_profiles_ip', table_name='host_profiles')
    op.drop_index('ix_host_profiles_id', table_name='host_profiles')
    op.drop_table('host_profiles')

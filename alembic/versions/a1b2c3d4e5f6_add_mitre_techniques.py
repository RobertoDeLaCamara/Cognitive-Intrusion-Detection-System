"""add mitre_techniques and ja3 columns to alerts

Revision ID: a1b2c3d4e5f6
Revises: 72da55e575e8
Create Date: 2026-03-10 15:08:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = '72da55e575e8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('alerts', sa.Column('mitre_techniques', sa.JSON(), nullable=True))
    op.add_column('alerts', sa.Column('ja3_hash', sa.String(32), nullable=True))
    op.add_column('alerts', sa.Column('ja3_string', sa.Text(), nullable=True))
    op.create_index('ix_alerts_ja3_hash', 'alerts', ['ja3_hash'])


def downgrade() -> None:
    op.drop_index('ix_alerts_ja3_hash', table_name='alerts')
    op.drop_column('alerts', 'ja3_string')
    op.drop_column('alerts', 'ja3_hash')
    op.drop_column('alerts', 'mitre_techniques')

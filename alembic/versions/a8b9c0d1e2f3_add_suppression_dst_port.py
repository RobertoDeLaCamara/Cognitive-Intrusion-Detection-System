"""add dst_port to suppression_rules so a rule can be limited to one service

Revision ID: a8b9c0d1e2f3
Revises: f6a7b8c9d0e1
Create Date: 2026-10-31 22:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a8b9c0d1e2f3'
down_revision: Union[str, Sequence[str], None] = 'f6a7b8c9d0e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('suppression_rules') as batch:
        batch.add_column(sa.Column('dst_port', sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('suppression_rules') as batch:
        batch.drop_column('dst_port')

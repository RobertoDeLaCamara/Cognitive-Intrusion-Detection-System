"""add src_port to suppression_rules so a rule can match the replies of a service

Revision ID: b9c0d1e2f3a4
Revises: a8b9c0d1e2f3
Create Date: 2026-11-05 20:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b9c0d1e2f3a4'
down_revision: Union[str, Sequence[str], None] = 'a8b9c0d1e2f3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('suppression_rules') as batch:
        batch.add_column(sa.Column('src_port', sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('suppression_rules') as batch:
        batch.drop_column('src_port')

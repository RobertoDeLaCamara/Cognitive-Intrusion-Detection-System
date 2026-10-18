"""add alerts.source so the Guardian can tell detector alerts from API-submitted ones

Revision ID: d4e5f6a7b8c9
Revises: c3d8e1f4a7b2
Create Date: 2026-10-18 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, Sequence[str], None] = 'c3d8e1f4a7b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Existing rows are treated as detector alerts (the pre-column behaviour: the Guardian
    # acted on everything); server_default backfills them.
    op.add_column(
        'alerts',
        sa.Column('source', sa.String(length=20), nullable=False, server_default='detector'),
    )


def downgrade() -> None:
    with op.batch_alter_table('alerts') as batch:
        batch.drop_column('source')

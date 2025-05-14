"""Add aggregation and anomaly detection fields to rules

Revision ID: 0484ea48793d
Revises: 73752cf18145
Create Date: 2025-05-15 01:09:25.652401

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0484ea48793d'
down_revision: Union[str, None] = '73752cf18145'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass

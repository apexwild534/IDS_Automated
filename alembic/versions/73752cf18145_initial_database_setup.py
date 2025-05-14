"""Initial database setup

Revision ID: 73752cf18145
Revises: 
Create Date: 2025-05-15 01:02:39.427804

"""
from typing import Sequence, Union
from datetime import datetime
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '73752cf18145'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    op.create_table(
        'alerts',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('timestamp', sa.DateTime(), default=datetime.utcnow),
        sa.Column('severity', sa.String()),
        sa.Column('source_ip', sa.String(), nullable=True),
        sa.Column('destination_ip', sa.String(), nullable=True),
        sa.Column('description', sa.String())
    )
    op.create_table(
        'rules',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('name', sa.String(), unique=True, index=True),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('severity', sa.String()),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('data_source', sa.String(), default="both"),
        sa.Column('conditions', sa.JSON(), nullable=True),
        sa.Column('threshold_count', sa.Integer(), nullable=True),
        sa.Column('threshold_window', sa.Integer(), nullable=True),
        sa.Column('sequence', sa.JSON(), nullable=True),
        sa.Column('sequence_window', sa.Integer(), nullable=True),
        sa.Column('coincidence_conditions', sa.JSON(), nullable=True),
        sa.Column('coincidence_window', sa.Integer(), nullable=True),
        sa.Column('aggregation_field', sa.String(), nullable=True),
        sa.Column('aggregation_value', sa.String(), nullable=True),
        sa.Column('aggregation_count', sa.Integer(), nullable=True),
        sa.Column('aggregation_window', sa.Integer(), nullable=True),
        sa.Column('anomaly_field', sa.String(), nullable=True),
        sa.Column('anomaly_threshold_multiplier', sa.Float(), nullable=True),
        sa.Column('anomaly_window', sa.Integer(), nullable=True),
        sa.Column('anomaly_baseline_count', sa.Integer(), nullable=True)
    )

def downgrade():
    op.drop_table('rules')
    op.drop_table('alerts')
    op.drop_column('rules', 'anomaly_baseline_count')
    op.drop_column('rules', 'anomaly_window')
    op.drop_column('rules', 'anomaly_threshold_multiplier')
    op.drop_column('rules', 'anomaly_field')
    op.drop_column('rules', 'aggregation_window')
    op.drop_column('rules', 'aggregation_count')
    op.drop_column('rules', 'aggregation_value')
    op.drop_column('rules', 'aggregation_field')
    op.drop_column('rules', 'coincidence_window')
    op.drop_column('rules', 'coincidence_conditions')

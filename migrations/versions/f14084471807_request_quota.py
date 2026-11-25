"""Add request quotas for account, quiz access, and AI operations."""

import sqlalchemy as sa
from alembic import op

revision = "f14084471807"
down_revision = "f14084471806"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "request_quota",
        sa.Column("scope", sa.String(length=64), primary_key=True),
        sa.Column("window", sa.Integer(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        if_not_exists=True,
    )


def downgrade():
    op.drop_table("request_quota")

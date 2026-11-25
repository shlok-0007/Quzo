"""Store instructor-approved question explanations."""

import sqlalchemy as sa
from alembic import op

revision = "f14084471808"
down_revision = "f14084471807"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "question_explanation",
        sa.Column("question_id", sa.Integer(), primary_key=True),
        sa.Column("text", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["question_id"], ["question.id"], ondelete="CASCADE"),
        if_not_exists=True,
    )


def downgrade():
    op.drop_table("question_explanation")

"""Record the grading basis used at submission and regrade."""

import sqlalchemy as sa
from alembic import op

revision = "f14084471809"
down_revision = "f14084471808"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "grade_snapshot",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("result_id", sa.Integer(), nullable=False),
        sa.Column("graded_at", sa.DateTime(), nullable=False),
        sa.Column("basis", sa.JSON(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.ForeignKeyConstraint(["result_id"], ["result.id"], ondelete="CASCADE"),
        if_not_exists=True,
    )
    op.create_index(
        "ix_grade_snapshot_result_id", "grade_snapshot", ["result_id"], if_not_exists=True
    )


def downgrade():
    op.drop_table("grade_snapshot")

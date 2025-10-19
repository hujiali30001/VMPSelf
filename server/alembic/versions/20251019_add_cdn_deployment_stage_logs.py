"""Add stage logs and rollback link to CDN deployments

Revision ID: 20251019_add_cdn_deployment_stage_logs
Revises: 20251019_add_cdn_sudo_password
Create Date: 2025-10-19
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "20251019_add_cdn_deployment_stage_logs"
down_revision: Union[str, Sequence[str], None] = "20251019_add_cdn_sudo_password"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    sqlite = bind.dialect.name == "sqlite"

    if sqlite:
        with op.batch_alter_table("cdn_deployments") as batch_op:
            batch_op.add_column(sa.Column("stage_logs", sa.JSON(), nullable=True))
            batch_op.add_column(sa.Column("config_text", sa.Text(), nullable=True))
            batch_op.add_column(sa.Column("rolled_back_from_id", sa.Integer(), nullable=True))
            batch_op.create_foreign_key(
                "fk_cdn_deployments_rolled_back_from_id",
                "cdn_deployments",
                ["rolled_back_from_id"],
                ["id"],
                ondelete="SET NULL",
            )
            batch_op.create_index(
                "ix_cdn_deployments_rolled_back_from_id",
                ["rolled_back_from_id"],
                unique=False,
            )
    else:
        op.add_column("cdn_deployments", sa.Column("stage_logs", sa.JSON(), nullable=True))
        op.add_column("cdn_deployments", sa.Column("config_text", sa.Text(), nullable=True))
        op.add_column("cdn_deployments", sa.Column("rolled_back_from_id", sa.Integer(), nullable=True))
        op.create_foreign_key(
            "fk_cdn_deployments_rolled_back_from_id",
            "cdn_deployments",
            "cdn_deployments",
            ["rolled_back_from_id"],
            ["id"],
            ondelete="SET NULL",
        )
        op.create_index(
            "ix_cdn_deployments_rolled_back_from_id",
            "cdn_deployments",
            ["rolled_back_from_id"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    sqlite = bind.dialect.name == "sqlite"

    if sqlite:
        with op.batch_alter_table("cdn_deployments") as batch_op:
            batch_op.drop_index("ix_cdn_deployments_rolled_back_from_id")
            batch_op.drop_constraint("fk_cdn_deployments_rolled_back_from_id", type_="foreignkey")
            batch_op.drop_column("rolled_back_from_id")
            batch_op.drop_column("config_text")
            batch_op.drop_column("stage_logs")
    else:
        op.drop_index("ix_cdn_deployments_rolled_back_from_id", table_name="cdn_deployments")
        op.drop_constraint("fk_cdn_deployments_rolled_back_from_id", "cdn_deployments", type_="foreignkey")
        op.drop_column("cdn_deployments", "rolled_back_from_id")
        op.drop_column("cdn_deployments", "config_text")
        op.drop_column("cdn_deployments", "stage_logs")

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
    inspector = sa.inspect(bind)
    is_sqlite = bind.dialect.name == "sqlite"

    column_names = {column["name"] for column in inspector.get_columns("cdn_deployments")}

    if "stage_logs" not in column_names:
        op.add_column("cdn_deployments", sa.Column("stage_logs", sa.JSON(), nullable=True))
        column_names.add("stage_logs")

    if "config_text" not in column_names:
        op.add_column("cdn_deployments", sa.Column("config_text", sa.Text(), nullable=True))
        column_names.add("config_text")

    if "rolled_back_from_id" not in column_names:
        op.add_column("cdn_deployments", sa.Column("rolled_back_from_id", sa.Integer(), nullable=True))
        column_names.add("rolled_back_from_id")

    fk_names = {fk["name"] for fk in inspector.get_foreign_keys("cdn_deployments") if fk.get("name")}
    if (
        "rolled_back_from_id" in column_names
        and "fk_cdn_deployments_rolled_back_from_id" not in fk_names
        and not is_sqlite
    ):
        op.create_foreign_key(
            "fk_cdn_deployments_rolled_back_from_id",
            "cdn_deployments",
            "cdn_deployments",
            ["rolled_back_from_id"],
            ["id"],
            ondelete="SET NULL",
        )

    index_names = {index["name"] for index in inspector.get_indexes("cdn_deployments")}
    if (
        "rolled_back_from_id" in column_names
        and "ix_cdn_deployments_rolled_back_from_id" not in index_names
    ):
        op.create_index(
            "ix_cdn_deployments_rolled_back_from_id",
            "cdn_deployments",
            ["rolled_back_from_id"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    is_sqlite = bind.dialect.name == "sqlite"

    index_names = {index["name"] for index in inspector.get_indexes("cdn_deployments")}
    if "ix_cdn_deployments_rolled_back_from_id" in index_names:
        op.drop_index("ix_cdn_deployments_rolled_back_from_id", table_name="cdn_deployments")

    fk_names = {fk["name"] for fk in inspector.get_foreign_keys("cdn_deployments") if fk.get("name")}
    if "fk_cdn_deployments_rolled_back_from_id" in fk_names and not is_sqlite:
        op.drop_constraint("fk_cdn_deployments_rolled_back_from_id", "cdn_deployments", type_="foreignkey")

    column_names = {column["name"] for column in inspector.get_columns("cdn_deployments")}
    if "rolled_back_from_id" in column_names:
        op.drop_column("cdn_deployments", "rolled_back_from_id")
        column_names.remove("rolled_back_from_id")

    if "config_text" in column_names:
        op.drop_column("cdn_deployments", "config_text")
        column_names.remove("config_text")

    if "stage_logs" in column_names:
        op.drop_column("cdn_deployments", "stage_logs")

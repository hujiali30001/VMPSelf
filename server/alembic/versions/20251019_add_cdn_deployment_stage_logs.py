"""Add stage logs and rollback link to CDN deployments

Revision ID: 20251019_add_cdn_deployment_stage_logs
Revises: 20251019_add_cdn_sudo_password
Create Date: 2025-10-19
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


FK_NAME = "fk_cdn_deployments_rolled_back_from_id"
INDEX_NAME = "ix_cdn_deployments_rolled_back_from_id"


def _ensure_sqlite_fk(bind: sa.engine.Connection) -> None:
    inspector = sa.inspect(bind)
    fk_names = {fk.get("name") for fk in inspector.get_foreign_keys("cdn_deployments") if fk.get("name")}

    if FK_NAME in fk_names:
        index_names = {index.get("name") for index in inspector.get_indexes("cdn_deployments")}
        if INDEX_NAME not in index_names:
            op.create_index(INDEX_NAME, "cdn_deployments", ["rolled_back_from_id"], unique=False)
        return

    existing_indexes = inspector.get_indexes("cdn_deployments")
    existing_columns = inspector.get_columns("cdn_deployments")
    existing_column_names = [column["name"] for column in existing_columns]

    op.execute("PRAGMA foreign_keys=OFF")
    try:
        op.rename_table("cdn_deployments", "_alembic_tmp_cdn_deployments")

        op.create_table(
            "cdn_deployments",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("endpoint_id", sa.Integer(), nullable=False),
            sa.Column("task_id", sa.Integer(), nullable=True),
            sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
            sa.Column("mode", sa.String(length=16), nullable=False, server_default="http"),
            sa.Column("allow_http", sa.Boolean(), nullable=False, server_default=sa.text("1")),
            sa.Column("proxy_protocol", sa.Boolean(), nullable=False, server_default=sa.text("0")),
            sa.Column("summary", sa.Text(), nullable=True),
            sa.Column("log", sa.Text(), nullable=True),
            sa.Column("config_snapshot", sa.JSON(), nullable=True),
            sa.Column("initiated_by", sa.String(length=128), nullable=True),
            sa.Column("initiated_by_id", sa.Integer(), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("duration_ms", sa.Integer(), nullable=True),
            sa.Column("stage_logs", sa.JSON(), nullable=True),
            sa.Column("config_text", sa.Text(), nullable=True),
            sa.Column("rolled_back_from_id", sa.Integer(), nullable=True),
            sa.ForeignKeyConstraint(["endpoint_id"], ["cdn_endpoints.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["task_id"], ["cdn_tasks.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["rolled_back_from_id"], ["cdn_deployments.id"], name=FK_NAME, ondelete="SET NULL"),
        )

        target_columns = [
            "id",
            "endpoint_id",
            "task_id",
            "status",
            "mode",
            "allow_http",
            "proxy_protocol",
            "summary",
            "log",
            "config_snapshot",
            "initiated_by",
            "initiated_by_id",
            "started_at",
            "completed_at",
            "duration_ms",
            "stage_logs",
            "config_text",
            "rolled_back_from_id",
        ]

        insert_columns_sql = ", ".join(f'"{column}"' for column in target_columns)
        select_columns_sql = ", ".join(
            (f'"{column}"' if column in existing_column_names else "NULL")
            for column in target_columns
        )

        op.execute(
            sa.text(
                f"INSERT INTO cdn_deployments ({insert_columns_sql}) "
                f"SELECT {select_columns_sql} FROM _alembic_tmp_cdn_deployments"
            )
        )

        op.drop_table("_alembic_tmp_cdn_deployments")
    finally:
        op.execute("PRAGMA foreign_keys=ON")

    recreated_indexes = set()
    for index in existing_indexes:
        name = index.get("name")
        column_names = index.get("column_names")
        if not name or not column_names:
            continue
        op.create_index(name, "cdn_deployments", column_names, unique=index.get("unique", False))
        recreated_indexes.add(name)

    if INDEX_NAME not in recreated_indexes:
        op.create_index(INDEX_NAME, "cdn_deployments", ["rolled_back_from_id"], unique=False)

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

    inspector = sa.inspect(bind)
    if is_sqlite:
        _ensure_sqlite_fk(bind)
    else:
        fk_names = {fk.get("name") for fk in inspector.get_foreign_keys("cdn_deployments") if fk.get("name")}
        if "rolled_back_from_id" in column_names and FK_NAME not in fk_names:
            op.create_foreign_key(
                FK_NAME,
                "cdn_deployments",
                "cdn_deployments",
                ["rolled_back_from_id"],
                ["id"],
                ondelete="SET NULL",
            )

        index_names = {index.get("name") for index in inspector.get_indexes("cdn_deployments")}
        if "rolled_back_from_id" in column_names and INDEX_NAME not in index_names:
            op.create_index(
                INDEX_NAME,
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

    fk_names = {fk.get("name") for fk in inspector.get_foreign_keys("cdn_deployments") if fk.get("name")}
    if FK_NAME in fk_names and not is_sqlite:
        op.drop_constraint(FK_NAME, "cdn_deployments", type_="foreignkey")

    column_names = {column["name"] for column in inspector.get_columns("cdn_deployments")}
    if "rolled_back_from_id" in column_names:
        op.drop_column("cdn_deployments", "rolled_back_from_id")
        column_names.remove("rolled_back_from_id")

    if "config_text" in column_names:
        op.drop_column("cdn_deployments", "config_text")
        column_names.remove("config_text")

    if "stage_logs" in column_names:
        op.drop_column("cdn_deployments", "stage_logs")

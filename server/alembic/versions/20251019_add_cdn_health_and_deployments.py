"""Add CDN deployment logs and health checks

Revision ID: 20251019_add_cdn_health_and_deployments
Revises: 20251019_extend_cdn_endpoints
Create Date: 2025-10-19
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "20251019_add_cdn_health_and_deployments"
down_revision: Union[str, None] = "20251019_extend_cdn_endpoints"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _add_endpoint_columns(sqlite: bool) -> None:
    columns = [
        sa.Column("health_status", sa.String(length=16), nullable=False, server_default="unknown"),
        sa.Column("health_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("health_latency_ms", sa.Integer(), nullable=True),
        sa.Column("health_error", sa.Text(), nullable=True),
    ]
    if sqlite:
        with op.batch_alter_table("cdn_endpoints") as batch_op:
            for column in columns:
                batch_op.add_column(column)
            batch_op.alter_column("health_status", server_default=None)
    else:
        for column in columns:
            op.add_column("cdn_endpoints", column)
        op.alter_column("cdn_endpoints", "health_status", server_default=None)


def _drop_endpoint_columns(sqlite: bool) -> None:
    column_names = [
        "health_error",
        "health_latency_ms",
        "health_checked_at",
        "health_status",
    ]
    if sqlite:
        with op.batch_alter_table("cdn_endpoints") as batch_op:
            for name in column_names:
                batch_op.drop_column(name)
    else:
        for name in column_names:
            op.drop_column("cdn_endpoints", name)


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    sqlite = dialect == "sqlite"

    _add_endpoint_columns(sqlite)

    op.create_table(
        "cdn_deployments",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("endpoint_id", sa.Integer(), sa.ForeignKey("cdn_endpoints.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("task_id", sa.Integer(), sa.ForeignKey("cdn_tasks.id", ondelete="SET NULL"), nullable=True, index=True),
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
    )

    op.create_index("ix_cdn_deployments_status", "cdn_deployments", ["status"])
    op.create_index("ix_cdn_deployments_started_at", "cdn_deployments", ["started_at"])

    op.create_table(
        "cdn_health_checks",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("endpoint_id", sa.Integer(), sa.ForeignKey("cdn_endpoints.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="unknown"),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_index("ix_cdn_health_checks_status", "cdn_health_checks", ["status"])
    op.create_index("ix_cdn_health_checks_checked_at", "cdn_health_checks", ["checked_at"])

    if dialect != "sqlite":
        op.alter_column("cdn_deployments", "status", server_default=None)
        op.alter_column("cdn_deployments", "mode", server_default=None)
        op.alter_column("cdn_deployments", "allow_http", server_default=None)
        op.alter_column("cdn_deployments", "proxy_protocol", server_default=None)
        op.alter_column("cdn_health_checks", "status", server_default=None)


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    sqlite = dialect == "sqlite"

    op.drop_index("ix_cdn_health_checks_checked_at", table_name="cdn_health_checks")
    op.drop_index("ix_cdn_health_checks_status", table_name="cdn_health_checks")
    op.drop_table("cdn_health_checks")

    op.drop_index("ix_cdn_deployments_started_at", table_name="cdn_deployments")
    op.drop_index("ix_cdn_deployments_status", table_name="cdn_deployments")
    op.drop_table("cdn_deployments")

    _drop_endpoint_columns(sqlite)

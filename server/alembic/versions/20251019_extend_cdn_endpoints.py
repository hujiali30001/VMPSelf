"""Extend CDN endpoints with deployment metadata

Revision ID: 20251019_extend_cdn_endpoints
Revises: 20251019_extend_audit_logs
Create Date: 2025-10-19
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision: str = "20251019_extend_cdn_endpoints"
down_revision: Union[str, None] = "20251019_extend_audit_logs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_NEW_COLUMNS = (
    sa.Column("host", sa.String(length=128), nullable=True),
    sa.Column("listen_port", sa.Integer(), nullable=True, server_default="443"),
    sa.Column("origin_port", sa.Integer(), nullable=True, server_default="443"),
    sa.Column("deployment_mode", sa.String(length=16), nullable=True, server_default="http"),
    sa.Column("ssh_username", sa.String(length=64), nullable=True),
    sa.Column("ssh_port", sa.Integer(), nullable=True, server_default="22"),
    sa.Column("ssh_password_encrypted", sa.Text(), nullable=True),
    sa.Column("ssh_private_key_encrypted", sa.Text(), nullable=True),
    sa.Column("edge_token", sa.String(length=128), nullable=True),
    sa.Column("last_deployed_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("last_deploy_status", sa.String(length=32), nullable=True),
)


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    inspector = inspect(bind)
    existing_columns = {col["name"] for col in inspector.get_columns("cdn_endpoints")}

    if "host" in existing_columns:
        return

    if dialect == "sqlite":
        with op.batch_alter_table("cdn_endpoints") as batch_op:
            for column in _NEW_COLUMNS:
                batch_op.add_column(column)
    else:
        for column in _NEW_COLUMNS:
            op.add_column("cdn_endpoints", column)

    bind.execute(
        sa.text(
            """
            UPDATE cdn_endpoints
            SET
                host = COALESCE(host, domain),
                ssh_username = COALESCE(ssh_username, 'root'),
                ssh_port = COALESCE(ssh_port, 22),
                listen_port = COALESCE(listen_port, 443),
                origin_port = COALESCE(origin_port, 443),
                deployment_mode = COALESCE(deployment_mode, 'http')
            """
        )
    )

    if dialect == "sqlite":
        with op.batch_alter_table("cdn_endpoints") as batch_op:
            batch_op.alter_column("host", existing_type=sa.String(length=128), nullable=False)
            batch_op.alter_column("ssh_username", existing_type=sa.String(length=64), nullable=False)
            batch_op.alter_column("ssh_port", existing_type=sa.Integer(), server_default=None, nullable=False)
            batch_op.alter_column("listen_port", existing_type=sa.Integer(), server_default=None, nullable=False)
            batch_op.alter_column("origin_port", existing_type=sa.Integer(), server_default=None, nullable=False)
            batch_op.alter_column("deployment_mode", existing_type=sa.String(length=16), server_default=None, nullable=False)
    else:
        op.alter_column("cdn_endpoints", "host", existing_type=sa.String(length=128), nullable=False)
        op.alter_column("cdn_endpoints", "ssh_username", existing_type=sa.String(length=64), nullable=False)
        op.alter_column(
            "cdn_endpoints",
            "ssh_port",
            existing_type=sa.Integer(),
            server_default=None,
            nullable=False,
        )
        op.alter_column(
            "cdn_endpoints",
            "listen_port",
            existing_type=sa.Integer(),
            server_default=None,
            nullable=False,
        )
        op.alter_column(
            "cdn_endpoints",
            "origin_port",
            existing_type=sa.Integer(),
            server_default=None,
            nullable=False,
        )
        op.alter_column(
            "cdn_endpoints",
            "deployment_mode",
            existing_type=sa.String(length=16),
            server_default=None,
            nullable=False,
        )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name

    columns = [
        "last_deploy_status",
        "last_deployed_at",
        "edge_token",
        "ssh_private_key_encrypted",
        "ssh_password_encrypted",
        "ssh_port",
        "ssh_username",
        "deployment_mode",
        "origin_port",
        "listen_port",
        "host",
    ]

    if dialect == "sqlite":
        with op.batch_alter_table("cdn_endpoints") as batch_op:
            for name in columns:
                batch_op.drop_column(name)
    else:
        for name in columns:
            op.drop_column("cdn_endpoints", name)

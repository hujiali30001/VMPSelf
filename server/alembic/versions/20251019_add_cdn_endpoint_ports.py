"""Add CDN endpoint port mappings table

Revision ID: 20251019_add_cdn_endpoint_ports
Revises: 20251019_add_cdn_deployment_stage_logs
Create Date: 2025-10-19
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "20251019_add_cdn_endpoint_ports"
down_revision: Union[str, Sequence[str], None] = "20251019_add_cdn_deployment_stage_logs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    sqlite = bind.dialect.name == "sqlite"

    if sqlite:
        with op.batch_alter_table("cdn_endpoints") as batch_op:
            batch_op.alter_column("listen_port", existing_type=sa.Integer(), nullable=True)
            batch_op.alter_column("origin_port", existing_type=sa.Integer(), nullable=True)
    else:
        op.alter_column("cdn_endpoints", "listen_port", existing_type=sa.Integer(), nullable=True)
        op.alter_column("cdn_endpoints", "origin_port", existing_type=sa.Integer(), nullable=True)

    op.create_table(
        "cdn_endpoint_ports",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("endpoint_id", sa.Integer(), sa.ForeignKey("cdn_endpoints.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("listen_port", sa.Integer(), nullable=False),
        sa.Column("origin_port", sa.Integer(), nullable=False),
        sa.Column("allow_http", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_index("ix_cdn_endpoint_ports_endpoint_id", "cdn_endpoint_ports", ["endpoint_id"])
    op.create_index("ix_cdn_endpoint_ports_listen", "cdn_endpoint_ports", ["listen_port"])

    if bind.dialect.name != "sqlite":
        op.alter_column("cdn_endpoint_ports", "created_at", server_default=None)


def downgrade() -> None:
    bind = op.get_bind()
    sqlite = bind.dialect.name == "sqlite"

    op.drop_index("ix_cdn_endpoint_ports_listen", table_name="cdn_endpoint_ports")
    op.drop_index("ix_cdn_endpoint_ports_endpoint_id", table_name="cdn_endpoint_ports")
    op.drop_table("cdn_endpoint_ports")

    if sqlite:
        with op.batch_alter_table("cdn_endpoints") as batch_op:
            batch_op.alter_column("origin_port", existing_type=sa.Integer(), nullable=False)
            batch_op.alter_column("listen_port", existing_type=sa.Integer(), nullable=False)
    else:
        op.alter_column("cdn_endpoints", "origin_port", existing_type=sa.Integer(), nullable=False)
        op.alter_column("cdn_endpoints", "listen_port", existing_type=sa.Integer(), nullable=False)

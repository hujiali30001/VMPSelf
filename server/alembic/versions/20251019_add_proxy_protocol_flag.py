"""Add proxy protocol flag to CDN endpoints

Also caches resolved egress IPs for origin whitelist recommendations.

Revision ID: 20251019_add_proxy_protocol_flag
Revises: 20251019_add_cdn_health_and_deployments
Create Date: 2025-10-19
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "20251019_add_proxy_protocol_flag"
down_revision: Union[str, None] = "20251019_add_cdn_health_and_deployments"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    sqlite = dialect == "sqlite"

    if sqlite:
        with op.batch_alter_table("cdn_endpoints") as batch_op:
            batch_op.add_column(sa.Column("proxy_protocol_enabled", sa.Boolean(), nullable=False, server_default=sa.text("0")))
            batch_op.add_column(sa.Column("egress_ips", sa.JSON(), nullable=True))
            batch_op.alter_column("proxy_protocol_enabled", server_default=None)
    else:
        op.add_column("cdn_endpoints", sa.Column("proxy_protocol_enabled", sa.Boolean(), nullable=False, server_default=sa.text("0")))
        op.add_column("cdn_endpoints", sa.Column("egress_ips", sa.JSON(), nullable=True))
        op.alter_column("cdn_endpoints", "proxy_protocol_enabled", server_default=None)


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    sqlite = dialect == "sqlite"

    if sqlite:
        with op.batch_alter_table("cdn_endpoints") as batch_op:
            batch_op.drop_column("egress_ips")
            batch_op.drop_column("proxy_protocol_enabled")
    else:
        op.drop_column("cdn_endpoints", "egress_ips")
        op.drop_column("cdn_endpoints", "proxy_protocol_enabled")

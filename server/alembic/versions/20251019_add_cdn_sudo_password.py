"""Add sudo password storage for CDN endpoints

Revision ID: 20251019_add_cdn_sudo_password
Revises: 20251019_merge_cdn_license_heads
Create Date: 2025-10-19
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision: str = "20251019_add_cdn_sudo_password"
down_revision: Union[str, Sequence[str], None] = "20251019_merge_cdn_license_heads"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    sqlite = bind.dialect.name == "sqlite"
    inspector = inspect(bind)

    existing_columns = {col["name"] for col in inspector.get_columns("cdn_endpoints")}
    if "sudo_password_encrypted" in existing_columns:
        return

    if sqlite:
        with op.batch_alter_table("cdn_endpoints") as batch_op:
            batch_op.add_column(sa.Column("sudo_password_encrypted", sa.Text(), nullable=True))
    else:
        op.add_column("cdn_endpoints", sa.Column("sudo_password_encrypted", sa.Text(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    sqlite = bind.dialect.name == "sqlite"

    if sqlite:
        with op.batch_alter_table("cdn_endpoints") as batch_op:
            batch_op.drop_column("sudo_password_encrypted")
    else:
        op.drop_column("cdn_endpoints", "sudo_password_encrypted")

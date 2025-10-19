"""Create access rules table

Revision ID: 20251020_add_access_rules
Revises: 20251019_add_cdn_endpoint_ports
Create Date: 2025-10-20
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20251020_add_access_rules"
down_revision: Union[str, Sequence[str], None] = "20251019_add_cdn_endpoint_ports"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


TABLE_NAME = "access_rules"


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    columns = [
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scope", sa.String(length=32), nullable=False),
        sa.Column("rule_type", sa.String(length=32), nullable=False),
        sa.Column("value", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    ]

    table_exists = inspector.has_table(TABLE_NAME)

    if not table_exists:
        op.create_table(
            TABLE_NAME,
            *columns,
            sa.UniqueConstraint(
                "scope", "rule_type", "value", name="uq_access_rules_scope_type_value"
            ),
        )

    existing_indexes = {index["name"] for index in inspector.get_indexes(TABLE_NAME)} if table_exists else set()

    if "ix_access_rules_scope" not in existing_indexes:
        op.create_index("ix_access_rules_scope", TABLE_NAME, ["scope"])

    if "ix_access_rules_rule_type" not in existing_indexes:
        op.create_index("ix_access_rules_rule_type", TABLE_NAME, ["rule_type"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    existing_indexes = {index["name"] for index in inspector.get_indexes(TABLE_NAME)}
    if "ix_access_rules_rule_type" in existing_indexes:
        op.drop_index("ix_access_rules_rule_type", table_name=TABLE_NAME)
    if "ix_access_rules_scope" in existing_indexes:
        op.drop_index("ix_access_rules_scope", table_name=TABLE_NAME)

    if inspector.has_table(TABLE_NAME):
        op.drop_table(TABLE_NAME)

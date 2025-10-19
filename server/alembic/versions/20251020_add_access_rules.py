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

    op.create_table(TABLE_NAME, *columns)
    op.create_index("ix_access_rules_scope", TABLE_NAME, ["scope"])
    op.create_index("ix_access_rules_rule_type", TABLE_NAME, ["rule_type"])
    op.create_unique_constraint(
        "uq_access_rules_scope_type_value",
        TABLE_NAME,
        ["scope", "rule_type", "value"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_access_rules_scope_type_value", TABLE_NAME, type_="unique")
    op.drop_index("ix_access_rules_rule_type", table_name=TABLE_NAME)
    op.drop_index("ix_access_rules_scope", table_name=TABLE_NAME)
    op.drop_table(TABLE_NAME)

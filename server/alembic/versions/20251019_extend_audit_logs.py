"""Enhance audit logs with actor and module metadata

Revision ID: 20251019_extend_audit_logs
Revises: 20251019_add_rbac_roles
Create Date: 2025-10-18
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "20251019_extend_audit_logs"
down_revision: Union[str, None] = "20251019_add_rbac_roles"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "sqlite":
        with op.batch_alter_table("audit_logs") as batch_op:
            batch_op.add_column(sa.Column("module", sa.String(length=64), nullable=True))
            batch_op.add_column(sa.Column("action", sa.String(length=64), nullable=True))
            batch_op.alter_column(
                "event_type",
                existing_type=sa.String(length=32),
                type_=sa.String(length=128),
                existing_nullable=False,
                nullable=True,
            )
            batch_op.add_column(
                sa.Column("actor_type", sa.String(length=32), nullable=True, server_default="system"),
            )
            batch_op.add_column(sa.Column("actor_id", sa.Integer(), nullable=True))
            batch_op.add_column(sa.Column("actor_name", sa.String(length=128), nullable=True))
            batch_op.add_column(sa.Column("actor_role", sa.String(length=64), nullable=True))
            batch_op.add_column(sa.Column("target_type", sa.String(length=64), nullable=True))
            batch_op.add_column(sa.Column("target_id", sa.String(length=128), nullable=True))
            batch_op.add_column(sa.Column("target_name", sa.String(length=255), nullable=True))
            batch_op.add_column(sa.Column("payload", sa.JSON(), nullable=True))
            batch_op.add_column(sa.Column("request_id", sa.String(length=128), nullable=True))
            batch_op.add_column(sa.Column("ip_address", sa.String(length=64), nullable=True))
    else:
        op.add_column("audit_logs", sa.Column("module", sa.String(length=64), nullable=True))
        op.add_column("audit_logs", sa.Column("action", sa.String(length=64), nullable=True))
        op.alter_column(
            "audit_logs",
            "event_type",
            existing_type=sa.String(length=32),
            type_=sa.String(length=128),
            existing_nullable=False,
            nullable=True,
        )
        op.add_column(
            "audit_logs",
            sa.Column("actor_type", sa.String(length=32), nullable=True, server_default="system"),
        )
        op.add_column("audit_logs", sa.Column("actor_id", sa.Integer(), nullable=True))
        op.add_column("audit_logs", sa.Column("actor_name", sa.String(length=128), nullable=True))
        op.add_column("audit_logs", sa.Column("actor_role", sa.String(length=64), nullable=True))
        op.add_column("audit_logs", sa.Column("target_type", sa.String(length=64), nullable=True))
        op.add_column("audit_logs", sa.Column("target_id", sa.String(length=128), nullable=True))
        op.add_column("audit_logs", sa.Column("target_name", sa.String(length=255), nullable=True))
        op.add_column("audit_logs", sa.Column("payload", sa.JSON(), nullable=True))
        op.add_column("audit_logs", sa.Column("request_id", sa.String(length=128), nullable=True))
        op.add_column("audit_logs", sa.Column("ip_address", sa.String(length=64), nullable=True))

    if dialect == "postgresql":
        bind.execute(
            sa.text(
                """
                UPDATE audit_logs
                SET module = COALESCE(NULLIF(split_part(event_type, ':', 1), ''), 'general'),
                    action = COALESCE(NULLIF(split_part(event_type, ':', 2), ''), event_type, 'unknown'),
                    actor_type = COALESCE(actor_type, 'system')
                """
            )
        )
    else:
        bind.execute(
            sa.text(
                """
                UPDATE audit_logs
                SET module = COALESCE(module, 'general'),
                    action = COALESCE(action, event_type, 'unknown'),
                    actor_type = COALESCE(actor_type, 'system')
                """
            )
        )

    if dialect == "sqlite":
        with op.batch_alter_table("audit_logs") as batch_op:
            batch_op.alter_column("module", existing_type=sa.String(length=64), nullable=False)
            batch_op.alter_column("action", existing_type=sa.String(length=64), nullable=False)
            batch_op.alter_column(
                "actor_type",
                existing_type=sa.String(length=32),
                nullable=False,
                server_default=None,
            )
            batch_op.create_index("ix_audit_logs_module", ["module"])
            batch_op.create_index("ix_audit_logs_action", ["action"])
            batch_op.create_index("ix_audit_logs_actor_type", ["actor_type"])
            batch_op.create_index("ix_audit_logs_actor_id", ["actor_id"])
            batch_op.create_index("ix_audit_logs_actor_role", ["actor_role"])
            batch_op.create_index("ix_audit_logs_target_type", ["target_type"])
            batch_op.create_index("ix_audit_logs_target_id", ["target_id"])
            batch_op.create_index("ix_audit_logs_license_id", ["license_id"])
            batch_op.create_index("ix_audit_logs_created_at", ["created_at"])
            batch_op.create_foreign_key(
                "fk_audit_logs_license_id",
                "licenses",
                ["license_id"],
                ["id"],
                ondelete="SET NULL",
            )
    else:
        op.alter_column("audit_logs", "module", existing_type=sa.String(length=64), nullable=False)
        op.alter_column("audit_logs", "action", existing_type=sa.String(length=64), nullable=False)
        op.alter_column(
            "audit_logs",
            "actor_type",
            existing_type=sa.String(length=32),
            nullable=False,
            server_default=None,
        )

        op.create_index("ix_audit_logs_module", "audit_logs", ["module"])
        op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
        op.create_index("ix_audit_logs_actor_type", "audit_logs", ["actor_type"])
        op.create_index("ix_audit_logs_actor_id", "audit_logs", ["actor_id"])
        op.create_index("ix_audit_logs_actor_role", "audit_logs", ["actor_role"])
        op.create_index("ix_audit_logs_target_type", "audit_logs", ["target_type"])
        op.create_index("ix_audit_logs_target_id", "audit_logs", ["target_id"])
        op.create_index("ix_audit_logs_license_id", "audit_logs", ["license_id"])
        op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])

        op.create_foreign_key(
            "fk_audit_logs_license_id",
            "audit_logs",
            "licenses",
            ["license_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "sqlite":
        with op.batch_alter_table("audit_logs") as batch_op:
            batch_op.drop_constraint("fk_audit_logs_license_id", type_="foreignkey")
            batch_op.drop_index("ix_audit_logs_created_at")
            batch_op.drop_index("ix_audit_logs_target_id")
            batch_op.drop_index("ix_audit_logs_target_type")
            batch_op.drop_index("ix_audit_logs_actor_role")
            batch_op.drop_index("ix_audit_logs_actor_id")
            batch_op.drop_index("ix_audit_logs_actor_type")
            batch_op.drop_index("ix_audit_logs_action")
            batch_op.drop_index("ix_audit_logs_module")
            batch_op.drop_index("ix_audit_logs_license_id")

            batch_op.alter_column(
                "actor_type",
                existing_type=sa.String(length=32),
                nullable=True,
                server_default=None,
            )
            batch_op.alter_column(
                "event_type",
                existing_type=sa.String(length=128),
                type_=sa.String(length=32),
                nullable=False,
            )

            batch_op.drop_column("ip_address")
            batch_op.drop_column("request_id")
            batch_op.drop_column("payload")
            batch_op.drop_column("target_name")
            batch_op.drop_column("target_id")
            batch_op.drop_column("target_type")
            batch_op.drop_column("actor_role")
            batch_op.drop_column("actor_name")
            batch_op.drop_column("actor_id")
            batch_op.drop_column("actor_type")
            batch_op.drop_column("action")
            batch_op.drop_column("module")
    else:
        op.drop_constraint("fk_audit_logs_license_id", "audit_logs", type_="foreignkey")
        op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
        op.drop_index("ix_audit_logs_target_id", table_name="audit_logs")
        op.drop_index("ix_audit_logs_target_type", table_name="audit_logs")
        op.drop_index("ix_audit_logs_actor_role", table_name="audit_logs")
        op.drop_index("ix_audit_logs_actor_id", table_name="audit_logs")
        op.drop_index("ix_audit_logs_actor_type", table_name="audit_logs")
        op.drop_index("ix_audit_logs_action", table_name="audit_logs")
        op.drop_index("ix_audit_logs_module", table_name="audit_logs")
        op.drop_index("ix_audit_logs_license_id", table_name="audit_logs")

        op.alter_column(
            "audit_logs",
            "actor_type",
            existing_type=sa.String(length=32),
            nullable=True,
        )
        op.alter_column(
            "audit_logs",
            "event_type",
            existing_type=sa.String(length=128),
            type_=sa.String(length=32),
            nullable=False,
        )

        op.drop_column("audit_logs", "ip_address")
        op.drop_column("audit_logs", "request_id")
        op.drop_column("audit_logs", "payload")
        op.drop_column("audit_logs", "target_name")
        op.drop_column("audit_logs", "target_id")
        op.drop_column("audit_logs", "target_type")
        op.drop_column("audit_logs", "actor_role")
        op.drop_column("audit_logs", "actor_name")
        op.drop_column("audit_logs", "actor_id")
        op.drop_column("audit_logs", "actor_type")
        op.drop_column("audit_logs", "action")
        op.drop_column("audit_logs", "module")

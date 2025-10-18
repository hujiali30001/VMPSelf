"""Introduce RBAC roles and permissions

Revision ID: 20251019_add_rbac_roles
Revises: 20251019_add_license_slot_fk
Create Date: 2025-10-18
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "20251019_add_rbac_roles"
down_revision: Union[str, None] = "20251019_add_license_slot_fk"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "roles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("code", sa.String(length=32), nullable=False, unique=True),
        sa.Column("display_name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "role_permissions",
    sa.Column("id", sa.Integer(), primary_key=True),
    sa.Column("role_id", sa.Integer(), nullable=False),
        sa.Column("module", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("role_id", "module", "action", name="uq_role_permissions_role_module_action"),
    )

    op.add_column("admin_users", sa.Column("role_id", sa.Integer(), nullable=True))
    op.create_index("ix_admin_users_role_id", "admin_users", ["role_id"], unique=False)
    op.create_foreign_key("fk_admin_users_role_id", "admin_users", "roles", ["role_id"], ["id"], ondelete="RESTRICT")

    roles_table = sa.table(
        "roles",
        sa.column("id", sa.Integer),
        sa.column("code", sa.String),
        sa.column("display_name", sa.String),
        sa.column("description", sa.Text),
        sa.column("is_active", sa.Boolean),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )

    role_permissions_table = sa.table(
        "role_permissions",
        sa.column("id", sa.Integer),
        sa.column("role_id", sa.Integer),
        sa.column("module", sa.String),
        sa.column("action", sa.String),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )

    now = datetime.now(timezone.utc)

    default_roles = [
        {"id": 1, "code": "superadmin", "display_name": "超级管理员", "description": "拥有全部系统权限", "is_active": True, "created_at": now, "updated_at": now},
        {"id": 2, "code": "admin", "display_name": "管理员", "description": "管理全部核心模块", "is_active": True, "created_at": now, "updated_at": now},
        {"id": 3, "code": "operator", "display_name": "运维人员", "description": "日常运营操作权限", "is_active": True, "created_at": now, "updated_at": now},
        {"id": 4, "code": "viewer", "display_name": "观察者", "description": "只读访问权限", "is_active": True, "created_at": now, "updated_at": now},
    ]
    op.bulk_insert(roles_table, default_roles)

    default_permissions = {
        "superadmin": [
            ("dashboard", "manage"),
            ("licenses", "manage"),
            ("users", "manage"),
            ("software", "manage"),
            ("cdn", "manage"),
            ("settings", "manage"),
        ],
        "admin": [
            ("dashboard", "manage"),
            ("licenses", "manage"),
            ("users", "manage"),
            ("software", "manage"),
            ("cdn", "manage"),
            ("settings", "manage"),
        ],
        "operator": [
            ("dashboard", "view"),
            ("licenses", "manage"),
            ("users", "manage"),
            ("software", "manage"),
            ("cdn", "manage"),
        ],
        "viewer": [
            ("dashboard", "view"),
            ("licenses", "view"),
            ("users", "view"),
            ("software", "view"),
            ("cdn", "view"),
        ],
    }

    role_code_to_id = {role["code"]: role["id"] for role in default_roles}
    permission_rows = []
    perm_id = 1
    for code, permissions in default_permissions.items():
        role_id = role_code_to_id[code]
        for module, action in permissions:
            permission_rows.append(
                {
                    "id": perm_id,
                    "role_id": role_id,
                    "module": module,
                    "action": action,
                    "created_at": now,
                }
            )
            perm_id += 1

    if permission_rows:
        op.bulk_insert(role_permissions_table, permission_rows)

    bind = op.get_bind()
    admin_users = list(bind.execute(sa.text("SELECT id, role FROM admin_users")))

    for admin_row in admin_users:
        admin_id = admin_row[0]
        current_role_code = (admin_row[1] or "admin").strip().lower()
        target_role_id = role_code_to_id.get(current_role_code, role_code_to_id["admin"])
        bind.execute(
            sa.text("UPDATE admin_users SET role_id = :role_id WHERE id = :admin_id"),
            {"role_id": target_role_id, "admin_id": admin_id},
        )

    bind.execute(
        sa.text(
            "UPDATE admin_users SET role_id = :role_id WHERE role_id IS NULL"
        ),
        {"role_id": role_code_to_id["admin"]},
    )

    op.alter_column("admin_users", "role_id", existing_type=sa.Integer(), nullable=False)
    op.drop_column("admin_users", "role")


def downgrade() -> None:
    op.add_column("admin_users", sa.Column("role", sa.String(length=32), nullable=True))

    bind = op.get_bind()
    result = list(bind.execute(sa.text("SELECT id, role_id FROM admin_users")))
    roles_map = {row[0]: row[1] for row in bind.execute(sa.text("SELECT id, code FROM roles"))}

    for admin_row in result:
        admin_id = admin_row[0]
        role_id = admin_row[1]
        role_code = roles_map.get(role_id, "admin")
        bind.execute(
            sa.text("UPDATE admin_users SET role = :role_code WHERE id = :admin_id"),
            {"role_code": role_code, "admin_id": admin_id},
        )

    op.drop_constraint("fk_admin_users_role_id", "admin_users", type_="foreignkey")
    op.drop_index("ix_admin_users_role_id", table_name="admin_users")
    op.drop_column("admin_users", "role_id")

    op.drop_table("role_permissions")
    op.drop_table("roles")

    bind.execute(sa.text("UPDATE admin_users SET role = 'admin' WHERE role IS NULL"))
    op.alter_column("admin_users", "role", existing_type=sa.String(length=32), nullable=False, server_default="admin")

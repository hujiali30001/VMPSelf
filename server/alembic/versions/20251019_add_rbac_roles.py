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
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision: str = "20251019_add_rbac_roles"
down_revision: Union[str, None] = "20251019_add_license_slot_fk"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    def _drop_sqlite_temp_table(name: str) -> None:
        if dialect == "sqlite":
            bind.execute(sa.text(f'DROP TABLE IF EXISTS "{name}"'))

    inspector = inspect(bind)
    temp_table_name = "_alembic_tmp_admin_users"

    if not inspector.has_table("roles"):
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

    inspector = inspect(bind)
    if not inspector.has_table("role_permissions"):
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

    inspector = inspect(bind)
    admin_columns = {col["name"] for col in inspector.get_columns("admin_users")}
    admin_indexes = {idx["name"] for idx in inspector.get_indexes("admin_users")}
    admin_fk_names = {fk.get("name") for fk in inspector.get_foreign_keys("admin_users") if fk.get("name")}

    role_column_exists = "role" in admin_columns
    role_id_exists = "role_id" in admin_columns

    if dialect == "sqlite":
        if not role_id_exists:
            _drop_sqlite_temp_table(temp_table_name)
            with op.batch_alter_table("admin_users") as batch_op:
                batch_op.add_column(sa.Column("role_id", sa.Integer(), nullable=True))
                batch_op.create_index("ix_admin_users_role_id", ["role_id"], unique=False)
                batch_op.create_foreign_key(
                    "fk_admin_users_role_id",
                    "roles",
                    ["role_id"],
                    ["id"],
                    ondelete="RESTRICT",
                )
            role_id_exists = True
        else:
            if "ix_admin_users_role_id" not in admin_indexes:
                _drop_sqlite_temp_table(temp_table_name)
                with op.batch_alter_table("admin_users") as batch_op:
                    batch_op.create_index("ix_admin_users_role_id", ["role_id"], unique=False)
            if "fk_admin_users_role_id" not in admin_fk_names:
                _drop_sqlite_temp_table(temp_table_name)
                with op.batch_alter_table("admin_users") as batch_op:
                    batch_op.create_foreign_key(
                        "fk_admin_users_role_id",
                        "roles",
                        ["role_id"],
                        ["id"],
                        ondelete="RESTRICT",
                    )
    else:
        if not role_id_exists:
            op.add_column("admin_users", sa.Column("role_id", sa.Integer(), nullable=True))
            role_id_exists = True
        if "ix_admin_users_role_id" not in admin_indexes:
            op.create_index("ix_admin_users_role_id", "admin_users", ["role_id"], unique=False)
        if "fk_admin_users_role_id" not in admin_fk_names:
            op.create_foreign_key(
                "fk_admin_users_role_id",
                "admin_users",
                "roles",
                ["role_id"],
                ["id"],
                ondelete="RESTRICT",
            )

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

    roles_count = bind.execute(sa.text("SELECT COUNT(*) FROM roles")).scalar()
    if roles_count == 0:
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

    role_rows = list(bind.execute(sa.text("SELECT id, code FROM roles")).mappings())
    role_code_to_id = {
        str(row["code"]).strip().lower(): row["id"]
        for row in role_rows
        if row.get("code") is not None
    }
    permission_rows = []
    perm_id = 1
    for code, permissions in default_permissions.items():
        role_id = role_code_to_id.get(code)
        if role_id is None:
            continue
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

    if bind.execute(sa.text("SELECT COUNT(*) FROM role_permissions")).scalar() == 0 and permission_rows:
        op.bulk_insert(role_permissions_table, permission_rows)

    admin_users = []
    if role_column_exists:
        admin_users = list(bind.execute(sa.text("SELECT id, role FROM admin_users")))

    default_role_id = role_code_to_id.get("admin") or next(iter(role_code_to_id.values()), None)

    for admin_row in admin_users:
        admin_id = admin_row[0]
        current_role_code = (admin_row[1] or "admin").strip().lower()
        target_role_id = role_code_to_id.get(current_role_code, default_role_id)
        if target_role_id is not None:
            bind.execute(
                sa.text("UPDATE admin_users SET role_id = :role_id WHERE id = :admin_id"),
                {"role_id": target_role_id, "admin_id": admin_id},
            )

    if default_role_id is not None:
        bind.execute(
            sa.text(
                "UPDATE admin_users SET role_id = :role_id WHERE role_id IS NULL"
            ),
            {"role_id": default_role_id},
        )

    if role_id_exists:
        if dialect == "sqlite":
            with op.batch_alter_table("admin_users") as batch_op:
                batch_op.alter_column("role_id", existing_type=sa.Integer(), nullable=False)
        else:
            op.alter_column("admin_users", "role_id", existing_type=sa.Integer(), nullable=False)

    if role_column_exists:
        if dialect == "sqlite":
            _drop_sqlite_temp_table(temp_table_name)
            with op.batch_alter_table("admin_users") as batch_op:
                batch_op.drop_column("role")
        else:
            op.drop_column("admin_users", "role")


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "sqlite":
        with op.batch_alter_table("admin_users") as batch_op:
            batch_op.add_column(sa.Column("role", sa.String(length=32), nullable=True))
    else:
        op.add_column("admin_users", sa.Column("role", sa.String(length=32), nullable=True))

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

    if dialect == "sqlite":
        with op.batch_alter_table("admin_users") as batch_op:
            batch_op.drop_constraint("fk_admin_users_role_id", type_="foreignkey")
            batch_op.drop_index("ix_admin_users_role_id")
            batch_op.drop_column("role_id")
    else:
        op.drop_constraint("fk_admin_users_role_id", "admin_users", type_="foreignkey")
        op.drop_index("ix_admin_users_role_id", table_name="admin_users")
        op.drop_column("admin_users", "role_id")

    op.drop_table("role_permissions")
    op.drop_table("roles")

    bind.execute(sa.text("UPDATE admin_users SET role = 'admin' WHERE role IS NULL"))
    if dialect == "sqlite":
        with op.batch_alter_table("admin_users") as batch_op:
            batch_op.alter_column(
                "role",
                existing_type=sa.String(length=32),
                nullable=False,
                server_default="admin",
            )
    else:
        op.alter_column("admin_users", "role", existing_type=sa.String(length=32), nullable=False, server_default="admin")

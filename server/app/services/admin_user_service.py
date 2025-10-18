from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, List, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.db import AdminUser, Role
from app.services.role_service import RoleService
from app.services import security


class AdminUserService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list_admins(self) -> List[AdminUser]:
        stmt = (
            select(AdminUser)
            .options(selectinload(AdminUser.role))
            .order_by(AdminUser.created_at.asc())
        )
        return list(self.db.scalars(stmt).all())

    def get_admin(self, admin_id: int) -> Optional[AdminUser]:
        stmt = (
            select(AdminUser)
            .options(selectinload(AdminUser.role))
            .where(AdminUser.id == admin_id)
        )
        return self.db.scalar(stmt)

    def find_by_username(self, username: str) -> Optional[AdminUser]:
        stmt = (
            select(AdminUser)
            .options(selectinload(AdminUser.role))
            .where(AdminUser.username == username)
        )
        return self.db.scalar(stmt)

    def create_admin(self, username: str, password: str, role_code: str = "admin") -> AdminUser:
        username = (username or "").strip()
        role_code = (role_code or "admin").strip().lower() or "admin"
        if len(username) < 3:
            raise ValueError("username_too_short")
        if len(password) < 8:
            raise ValueError("password_too_short")

        if self.find_by_username(username):
            raise ValueError("username_taken")

        role = self._require_active_role(role_code)

        admin = AdminUser(
            username=username,
            password_hash=security.hash_password(password),
            role=role,
        )
        self.db.add(admin)
        try:
            self.db.commit()
        except IntegrityError as exc:
            self.db.rollback()
            message = str(exc.orig).lower() if getattr(exc, "orig", None) else str(exc).lower()
            if "admin_users.username" in message:
                raise ValueError("username_taken")
            raise
        self.db.refresh(admin)
        return admin

    def reset_password(self, admin_id: int, password: str) -> AdminUser:
        if len(password) < 8:
            raise ValueError("password_too_short")
        admin = self.db.get(AdminUser, admin_id)
        if not admin:
            raise ValueError("admin_not_found")
        admin.password_hash = security.hash_password(password)
        admin.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(admin)
        return admin

    def set_active(self, admin_id: int, is_active: bool) -> AdminUser:
        admin = self.db.get(AdminUser, admin_id)
        if not admin:
            raise ValueError("admin_not_found")
        admin.is_active = is_active
        admin.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(admin)
        return admin

    def assign_role(self, admin_id: int, role_code: str) -> AdminUser:
        admin = self.db.get(AdminUser, admin_id)
        if not admin:
            raise ValueError("admin_not_found")
        admin.role = self._require_active_role(role_code)
        admin.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(admin)
        return admin

    def verify_credentials(self, username: str, password: str) -> Optional[AdminUser]:
        admin = self.find_by_username(username)
        if not admin or not admin.is_active:
            return None
        if not admin.role or not admin.role.is_active:
            return None
        if not security.verify_password(password, admin.password_hash):
            return None
        admin.last_login_at = datetime.now(timezone.utc)
        admin.updated_at = admin.last_login_at
        self.db.commit()
        self.db.refresh(admin)
        return admin

    def _require_active_role(self, role_code: str) -> Role:
        normalized = (role_code or "admin").strip().lower() or "admin"
        role_stmt = (
            select(Role)
            .where(Role.code == normalized)
            .where(Role.is_active.is_(True))
        )
        role = self.db.scalar(role_stmt)
        if not role:
            raise ValueError("role_not_found")
        return role

    def ensure_roles(self, roles: Iterable[tuple[str, str]] | None = None) -> None:
        """Ensure roles exist; helpful for bootstrap in tests."""
        roles = roles or (
            ("superadmin", "超级管理员"),
            ("admin", "管理员"),
            ("operator", "运维人员"),
            ("viewer", "观察者"),
        )
        existing = {
            code
            for code in self.db.scalars(select(Role.code)).all()
        }
        now = datetime.now(timezone.utc)
        for code, display_name in roles:
            code = code.strip().lower()
            if code in existing:
                continue
            role = Role(
                code=code,
                display_name=display_name,
                description=f"Auto-created role {display_name}",
                created_at=now,
                updated_at=now,
            )
            self.db.add(role)
        self.db.commit()

        role_service = RoleService(self.db)
        default_permissions: dict[str, Iterable[tuple[str, str]]] = {
            "superadmin": [("*", "*")],
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

        for code, permissions in default_permissions.items():
            role = role_service.get_role_by_code(code, include_inactive=True)
            if not role:
                continue
            if role.permissions:
                continue
            role_service.update_role(role.id, permissions=permissions)

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import AdminUser
from app.services import security


class AdminUserService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list_admins(self) -> List[AdminUser]:
        stmt = select(AdminUser).order_by(AdminUser.created_at.asc())
        return list(self.db.scalars(stmt).all())

    def get_admin(self, admin_id: int) -> Optional[AdminUser]:
        return self.db.get(AdminUser, admin_id)

    def find_by_username(self, username: str) -> Optional[AdminUser]:
        stmt = select(AdminUser).where(AdminUser.username == username)
        return self.db.scalar(stmt)

    def create_admin(self, username: str, password: str, role: str = "admin") -> AdminUser:
        username = (username or "").strip()
        role = (role or "admin").strip() or "admin"
        if len(username) < 3:
            raise ValueError("username_too_short")
        if len(password) < 8:
            raise ValueError("password_too_short")

        if self.find_by_username(username):
            raise ValueError("username_taken")

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

    def verify_credentials(self, username: str, password: str) -> Optional[AdminUser]:
        admin = self.find_by_username(username)
        if not admin or not admin.is_active:
            return None
        if not security.verify_password(password, admin.password_hash):
            return None
        admin.last_login_at = datetime.now(timezone.utc)
        admin.updated_at = admin.last_login_at
        self.db.commit()
        self.db.refresh(admin)
        return admin

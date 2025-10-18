from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import FrozenSet, Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBasicCredentials
from sqlalchemy.orm import Session
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from app.api.deps import get_db
from app.db import models
from app.services.accounts import AdminUserService
from app.services.audit import AuditActor

from .constants import basic_auth, settings


@dataclass(frozen=True)
class AdminPrincipal:
    id: Optional[int]
    username: str
    role_code: str
    role_display: str
    permissions: FrozenSet[tuple[str, str]]

    def has_permission(self, module: str, action: str) -> bool:
        if self.role_code == "superadmin":
            return True
        module_key = (module or "").strip().lower()
        action_key = (action or "").strip().lower()
        if not module_key or not action_key:
            return False
        if (module_key, action_key) in self.permissions:
            return True
        if (module_key, "*") in self.permissions:
            return True
        if ("*", action_key) in self.permissions:
            return True
        if ("*", "*") in self.permissions:
            return True
        return False


def build_admin_principal(admin: models.AdminUser) -> AdminPrincipal:
    permissions = frozenset((perm.module, perm.action) for perm in admin.role.permissions)
    return AdminPrincipal(
        id=admin.id,
        username=admin.username,
        role_code=admin.role.code,
        role_display=admin.role.display_name,
        permissions=permissions,
    )


def build_audit_actor(principal: Optional[AdminPrincipal] = None) -> AuditActor:
    if not principal:
        return AuditActor()
    actor_type = "superadmin" if principal.role_code == "superadmin" else "admin_user"
    return AuditActor(
        type=actor_type,
        id=principal.id,
        name=principal.username,
        role=principal.role_code,
    )


def require_admin(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(basic_auth),
    db: Session = Depends(get_db),
) -> AdminPrincipal:
    admin_service = AdminUserService(db)
    admin = admin_service.verify_credentials(credentials.username, credentials.password)
    if admin:
        principal = build_admin_principal(admin)
        request.state.admin_identity = {
            "id": admin.id,
            "name": admin.username,
            "role": admin.role.code,
            "role_display": admin.role.display_name,
            "last_login_at": admin.last_login_at,
            "permissions": list(principal.permissions),
        }
        request.state.admin_principal = principal
        return principal

    username_match = secrets.compare_digest(credentials.username, settings.admin_username)
    password_match = secrets.compare_digest(credentials.password, settings.admin_password)
    if username_match and password_match:
        principal = AdminPrincipal(
            id=None,
            username=settings.admin_username,
            role_code="superadmin",
            role_display="系统超级管理员",
            permissions=frozenset({("*", "*")}),
        )
        request.state.admin_identity = {
            "name": settings.admin_username,
            "role": "superadmin",
            "role_display": "系统超级管理员",
            "permissions": [("*", "*")],
        }
        request.state.admin_principal = principal
        return principal

    raise HTTPException(
        status_code=HTTP_401_UNAUTHORIZED,
        detail="Unauthorized",
        headers={"WWW-Authenticate": "Basic"},
    )


def require_permission(module: str, action: str):
    normalized_module = (module or "").strip().lower()
    normalized_action = (action or "").strip().lower()

    if not normalized_module:
        raise ValueError("module_required")
    if not normalized_action:
        raise ValueError("action_required")

    def _dependency(principal: AdminPrincipal = Depends(require_admin)) -> AdminPrincipal:
        if principal.has_permission(normalized_module, normalized_action):
            return principal
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="forbidden")

    return _dependency


__all__ = [
    "AdminPrincipal",
    "basic_auth",
    "build_admin_principal",
    "build_audit_actor",
    "require_admin",
    "require_permission",
]

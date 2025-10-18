from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.db import Role, RolePermission
from app.services.audit import AuditActor, AuditService, AuditTarget


@dataclass(frozen=True)
class Permission:
    module: str
    action: str


class RoleService:
    def __init__(self, db: Session, *, actor: Optional[AuditActor] = None) -> None:
        self.db = db
        self._actor = actor
        self.audit = AuditService(db)

    def list_roles(self, include_inactive: bool = False) -> List[Role]:
        stmt = select(Role).options(selectinload(Role.permissions)).order_by(Role.id.asc())
        if not include_inactive:
            stmt = stmt.where(Role.is_active.is_(True))
        return list(self.db.scalars(stmt).unique().all())

    def get_role(self, role_id: int) -> Optional[Role]:
        stmt = (
            select(Role)
            .options(selectinload(Role.permissions))
            .where(Role.id == role_id)
        )
        return self.db.scalar(stmt)

    def get_role_by_code(self, code: str, *, include_inactive: bool = False) -> Optional[Role]:
        if not code:
            return None
        normalized = code.strip().lower()
        stmt = (
            select(Role)
            .options(selectinload(Role.permissions))
            .where(Role.code == normalized)
        )
        if not include_inactive:
            stmt = stmt.where(Role.is_active.is_(True))
        return self.db.scalar(stmt)

    def create_role(
        self,
        code: str,
        display_name: str,
        description: str = "",
        *,
        permissions: Optional[Iterable[Tuple[str, str]]] = None,
    ) -> Role:
        normalized = (code or "").strip().lower()
        if len(normalized) < 2:
            raise ValueError("role_code_too_short")
        if self.get_role_by_code(normalized, include_inactive=True):
            raise ValueError("role_code_taken")

        role = Role(
            code=normalized,
            display_name=display_name.strip() or normalized,
            description=description.strip() if description else None,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        self.db.add(role)
        self.db.flush()

        added: set[tuple[str, str]] = set()
        if permissions:
            added, _ = self._replace_permissions(role, permissions)

        self._log_action(
            "create",
            role,
            message=f"创建角色 {role.display_name}",
            payload={
                "code": role.code,
                "permissions_added": sorted(added),
            },
        )
        self.db.commit()
        self.db.refresh(role)
        return role

    def update_role(
        self,
        role_id: int,
        *,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        is_active: Optional[bool] = None,
        permissions: Optional[Iterable[Tuple[str, str]]] = None,
    ) -> Role:
        role = self.get_role(role_id)
        if not role:
            raise ValueError("role_not_found")

        if display_name is not None:
            role.display_name = display_name.strip() or role.display_name
        if description is not None:
            role.description = description.strip() or None
        if is_active is not None:
            role.is_active = bool(is_active)
        role.updated_at = datetime.now(timezone.utc)

        added: set[tuple[str, str]] = set()
        removed: set[tuple[str, str]] = set()
        if permissions is not None:
            added, removed = self._replace_permissions(role, permissions)

        self._log_action(
            "update",
            role,
            message=f"更新角色 {role.display_name}",
            payload={
                "code": role.code,
                "display_name": role.display_name,
                "is_active": role.is_active,
                "permissions_added": sorted(added),
                "permissions_removed": sorted(removed),
            },
        )
        self.db.commit()
        self.db.refresh(role)
        return role

    def has_permission(self, role: Optional[Role], module: str, action: str) -> bool:
        if not role or not role.is_active:
            return False
        if role.code == "superadmin":
            return True
        module_key = (module or "").strip().lower()
        action_key = (action or "").strip().lower()
        if not module_key or not action_key:
            return False
        for perm in role.permissions:
            if perm.module == module_key and (perm.action == action_key or perm.action == "*"):
                return True
            if perm.module == "*" and (perm.action == action_key or perm.action == "*"):
                return True
        return False

    def export_permissions(self) -> dict[str, List[Permission]]:
        result: dict[str, List[Permission]] = defaultdict(list)
        stmt = select(Role).options(selectinload(Role.permissions))
        for role in self.db.scalars(stmt).unique().all():
            perms = [Permission(module=perm.module, action=perm.action) for perm in role.permissions]
            result[role.code] = perms
        return result

    def _replace_permissions(self, role: Role, permissions: Iterable[Tuple[str, str]]) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
        normalized_new = {
            (module.strip().lower(), action.strip().lower())
            for module, action in permissions
            if module and action
        }
        existing = {
            (perm.module, perm.action): perm
            for perm in list(role.permissions)
        }

        removed: set[tuple[str, str]] = set()
        for key, perm in existing.items():
            if key not in normalized_new:
                self.db.delete(perm)
                removed.add(key)

        added: set[tuple[str, str]] = set()
        for module, action in normalized_new:
            if (module, action) not in existing:
                self.db.add(
                    RolePermission(
                        role=role,
                        module=module,
                        action=action,
                        created_at=datetime.now(timezone.utc),
                    )
                )
                added.add((module, action))
        role.updated_at = datetime.now(timezone.utc)
        self.db.flush()
        return added, removed

    def _log_action(
        self,
        action: str,
        role: Role,
        *,
        message: Optional[str] = None,
        payload: Optional[dict[str, object]] = None,
    ) -> None:
        target = AuditTarget(
            type="role",
            id=str(role.id) if role.id is not None else None,
            name=role.display_name,
        )
        self.audit.log_event(
            module="roles",
            action=action,
            actor=self._actor,
            target=target,
            message=message,
            payload=payload,
        )

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Optional

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.db import models


@dataclass(frozen=True)
class AuditActor:
    """Represents the subject who triggered an audit event."""

    type: str = "system"
    id: Optional[int] = None
    name: Optional[str] = None
    role: Optional[str] = None


@dataclass(frozen=True)
class AuditTarget:
    """Represents the entity affected by an audit event."""

    type: Optional[str] = None
    id: Optional[str] = None
    name: Optional[str] = None
    license_id: Optional[int] = None


class AuditService:
    """Centralised audit logging utilities."""

    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------
    def log_event(
        self,
        *,
        module: str,
        action: str,
        actor: Optional[AuditActor] = None,
        target: Optional[AuditTarget] = None,
        message: Optional[str] = None,
        payload: Optional[dict[str, Any]] = None,
        request_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> models.AuditLog:
        """Persist a generic audit record."""

        normalized_module = self._normalize_key(module) or "general"
        normalized_action = self._normalize_key(action) or "unknown"
        actor = actor or AuditActor()
        normalized_actor_type = self._normalize_key(actor.type) or "system"

        normalized_target_type: Optional[str] = None
        normalized_target_id: Optional[str] = None
        target_name: Optional[str] = None
        license_id: Optional[int] = None

        if target:
            normalized_target_type = self._normalize_key(target.type) if target.type else None
            if target.id is not None:
                normalized_target_id = str(target.id)
            target_name = self._normalize_text(target.name)
            license_id = target.license_id

        log = models.AuditLog(
            module=normalized_module,
            action=normalized_action,
            actor_type=normalized_actor_type,
            actor_id=actor.id,
            actor_name=self._normalize_text(actor.name),
            actor_role=self._normalize_key(actor.role),
            target_type=normalized_target_type,
            target_id=normalized_target_id,
            target_name=target_name,
            license_id=license_id,
            message=message,
            payload=payload,
            request_id=self._normalize_text(request_id),
            ip_address=self._normalize_text(ip_address),
        )
        self.db.add(log)
        return log

    def log_license_event(
        self,
        license_obj: models.License,
        *,
        action: str,
        actor: Optional[AuditActor] = None,
        message: Optional[str] = None,
        payload: Optional[dict[str, Any]] = None,
        request_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> models.AuditLog:
        """Log an event that targets a license record."""

        license_id = license_obj.id
        if license_id is None:
            self.db.flush()
            license_id = license_obj.id

        target = AuditTarget(
            type="license",
            id=str(license_id) if license_id is not None else None,
            name=license_obj.card_code,
            license_id=license_id,
        )
        return self.log_event(
            module="licenses",
            action=action,
            actor=actor,
            target=target,
            message=message,
            payload=payload,
            request_id=request_id,
            ip_address=ip_address,
        )

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------
    def list_logs(
        self,
        *,
        module: Optional[str] = None,
        action: Optional[str] = None,
        actor_type: Optional[str] = None,
        actor_id: Optional[int] = None,
        actor_role: Optional[str] = None,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        license_id: Optional[int] = None,
        search: Optional[str] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[models.AuditLog], int]:
        """List audit logs with optional filters and return (items, total)."""

        if limit <= 0:
            limit = 50
        limit = min(limit, 200)
        offset = max(offset, 0)

        stmt = select(models.AuditLog)
        stmt = self._apply_filters(
            stmt,
            module=module,
            action=action,
            actor_type=actor_type,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type=target_type,
            target_id=target_id,
            license_id=license_id,
            search=search,
            start=start,
            end=end,
        )

        total_stmt = select(func.count()).select_from(stmt.subquery())
        total = self.db.scalar(total_stmt) or 0

        stmt = (
            stmt.order_by(models.AuditLog.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        results = list(self.db.scalars(stmt).all())
        return results, int(total)

    def list_logs_for_license(
        self,
        license_id: int,
        *,
        limit: int = 100,
    ) -> list[models.AuditLog]:
        logs, _ = self.list_logs(license_id=license_id, limit=limit, offset=0)
        return logs

    # ------------------------------------------------------------------
    # Internal utilities
    # ------------------------------------------------------------------
    def _apply_filters(
        self,
        stmt,
        *,
        module: Optional[str],
        action: Optional[str],
        actor_type: Optional[str],
        actor_id: Optional[int],
        actor_role: Optional[str],
        target_type: Optional[str],
        target_id: Optional[str],
        license_id: Optional[int],
        search: Optional[str],
        start: Optional[datetime],
        end: Optional[datetime],
    ):
        conditions: list[Any] = []
        if module:
            conditions.append(models.AuditLog.module == self._normalize_key(module))
        if action:
            conditions.append(models.AuditLog.action == self._normalize_key(action))
        if actor_type:
            conditions.append(models.AuditLog.actor_type == self._normalize_key(actor_type))
        if actor_id is not None:
            conditions.append(models.AuditLog.actor_id == actor_id)
        if actor_role:
            conditions.append(models.AuditLog.actor_role == self._normalize_key(actor_role))
        if target_type:
            conditions.append(models.AuditLog.target_type == self._normalize_key(target_type))
        if target_id:
            conditions.append(models.AuditLog.target_id == str(target_id))
        if license_id is not None:
            conditions.append(models.AuditLog.license_id == license_id)
        if start:
            conditions.append(models.AuditLog.created_at >= start)
        if end:
            conditions.append(models.AuditLog.created_at <= end)

        if search:
            pattern = f"%{search.strip()}%"
            conditions.append(
                or_(
                    models.AuditLog.message.ilike(pattern),
                    models.AuditLog.actor_name.ilike(pattern),
                    models.AuditLog.target_name.ilike(pattern),
                )
            )

        if conditions:
            stmt = stmt.where(and_(*conditions))
        return stmt

    @staticmethod
    def _normalize_key(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip().lower()
        return normalized or None

    @staticmethod
    def _normalize_text(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


__all__ = ["AuditService", "AuditActor", "AuditTarget"]

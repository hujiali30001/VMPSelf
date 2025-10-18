from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import (
    CDNEndpoint,
    CDNEndpointStatus,
    CDNTask,
    CDNTaskStatus,
    CDNTaskType,
)


class CDNService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # Endpoints -----------------------------------------------------------------
    def list_endpoints(self) -> List[CDNEndpoint]:
        stmt = select(CDNEndpoint).order_by(CDNEndpoint.created_at.desc())
        return list(self.db.scalars(stmt).all())

    def get_endpoint(self, endpoint_id: int) -> Optional[CDNEndpoint]:
        return self.db.get(CDNEndpoint, endpoint_id)

    def create_endpoint(
        self,
        *,
        name: str,
        domain: str,
        provider: str,
        origin: str,
        notes: Optional[str] = None,
    ) -> CDNEndpoint:
        name = (name or "").strip()
        domain = (domain or "").strip().lower()
        provider = (provider or "").strip()
        origin = (origin or "").strip()
        notes = (notes or "").strip() or None

        if len(name) < 3:
            raise ValueError("name_too_short")
        if not domain or "." not in domain:
            raise ValueError("domain_invalid")
        if not provider:
            raise ValueError("provider_required")
        if not origin:
            raise ValueError("origin_required")

        existing = self.db.scalar(select(CDNEndpoint).where(CDNEndpoint.domain == domain))
        if existing:
            raise ValueError("domain_exists")

        endpoint = CDNEndpoint(
            name=name,
            domain=domain,
            provider=provider,
            origin=origin,
            notes=notes,
        )
        self.db.add(endpoint)
        self.db.commit()
        self.db.refresh(endpoint)
        return endpoint

    def set_endpoint_status(self, endpoint_id: int, status: CDNEndpointStatus) -> CDNEndpoint:
        endpoint = self.db.get(CDNEndpoint, endpoint_id)
        if not endpoint:
            raise ValueError("endpoint_not_found")
        endpoint.status = status.value
        endpoint.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(endpoint)
        return endpoint

    # Tasks ----------------------------------------------------------------------
    def list_recent_tasks(self, limit: int = 20) -> List[CDNTask]:
        stmt = (
            select(CDNTask)
            .order_by(CDNTask.created_at.desc())
            .limit(max(1, min(limit, 100)))
        )
        return list(self.db.scalars(stmt).all())

    def create_task(
        self,
        *,
        endpoint_id: int,
        task_type: CDNTaskType,
        payload: Optional[str] = None,
    ) -> CDNTask:
        endpoint = self.db.get(CDNEndpoint, endpoint_id)
        if not endpoint:
            raise ValueError("endpoint_not_found")

        task = CDNTask(
            endpoint=endpoint,
            task_type=task_type.value,
            payload=payload.strip() if payload else None,
        )
        self.db.add(task)
        self.db.flush()

        # 模拟即时完成，后续可替换为实际异步任务
        now = datetime.now(timezone.utc)
        task.status = CDNTaskStatus.COMPLETED.value
        task.message = "Task simulated as completed"
        task.completed_at = now
        endpoint.updated_at = now

        self.db.commit()
        self.db.refresh(task)
        return task

    def mark_task_failed(self, task_id: int, message: str) -> CDNTask:
        task = self.db.get(CDNTask, task_id)
        if not task:
            raise ValueError("task_not_found")
        task.status = CDNTaskStatus.FAILED.value
        task.message = message
        task.completed_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(task)
        return task

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Callable, Optional

from sqlalchemy.orm import Session

from app.db import CDNEndpointStatus, CDNHealthStatus
from app.services.audit import AuditActor, AuditService, AuditTarget
from app.services.cdn.service import CDNService

logger = logging.getLogger(__name__)


class CDNHealthMonitor:
    """Background worker that periodically probes CDN endpoints."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        interval_seconds: int,
    ) -> None:
        self._session_factory = session_factory
        self._interval = max(30, interval_seconds)
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        logger.info("Starting CDN health monitor (interval=%ss)", self._interval)
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="cdn-health-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if not self._thread:
            return
        logger.info("Stopping CDN health monitor")
        self._stop_event.set()
        self._thread.join(timeout=self._interval)
        self._thread = None

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def update_interval(self, interval_seconds: int) -> None:
        sanitized = max(30, interval_seconds)
        if sanitized != self._interval:
            logger.info("Updating CDN health monitor interval: %s -> %s", self._interval, sanitized)
        self._interval = sanitized

    @property
    def interval_seconds(self) -> int:
        return self._interval

    def _run(self) -> None:
        # Run immediately, then wait for interval.
        while not self._stop_event.is_set():
            start = time.perf_counter()
            try:
                self._execute_cycle()
            except Exception as exc:  # pragma: no cover - defensive
                logger.error("CDN health monitor cycle failed", exc_info=exc)
            elapsed = time.perf_counter() - start
            wait_time = max(0, self._interval - elapsed)
            if self._stop_event.wait(wait_time):
                break

    def _execute_cycle(self) -> None:
        with self._session_factory() as session:
            service = CDNService(session)
            endpoints = service.list_endpoints()
            for endpoint in endpoints:
                if endpoint.status not in {
                    CDNEndpointStatus.ACTIVE.value,
                    CDNEndpointStatus.ERROR.value,
                }:
                    continue
                previous_status = endpoint.health_status or CDNHealthStatus.UNKNOWN.value
                try:
                    record = service.run_health_check(endpoint.id)
                except ValueError as exc:
                    logger.warning("Skipping health monitor for endpoint", exc_info=exc)
                    continue
                except Exception as exc:  # pragma: no cover - defensive
                    logger.error("Automated health check failed", extra={"endpoint": endpoint.id}, exc_info=exc)
                    session.rollback()
                    continue

                new_status = record.status
                if new_status in {CDNHealthStatus.UNHEALTHY.value, CDNHealthStatus.DEGRADED.value}:
                    if new_status != previous_status:
                        self._record_alert(session, endpoint.id, endpoint.name, new_status, record.message, record.latency_ms)
                elif previous_status in {CDNHealthStatus.UNHEALTHY.value, CDNHealthStatus.DEGRADED.value} and new_status == CDNHealthStatus.HEALTHY.value:
                    self._record_recovery(session, endpoint.id, endpoint.name)

    def _record_alert(
        self,
        session: Session,
        endpoint_id: int,
        endpoint_name: str,
        status: str,
        message: Optional[str],
        latency_ms: Optional[int],
    ) -> None:
        audit = AuditService(session)
        audit.log_event(
            module="cdn",
            action="health_alert",
            actor=AuditActor(type="system"),
            target=AuditTarget(type="cdn_endpoint", id=str(endpoint_id), name=endpoint_name),
            message=f"节点健康状态异常: {status}",
            payload={
                "status": status,
                "message": message,
                "latency_ms": latency_ms,
            },
        )
        session.commit()
        logger.warning(
            "CDN endpoint %s unhealthy (%s) -- latency=%s message=%s",
            endpoint_name,
            status,
            latency_ms,
            message,
        )

    def _record_recovery(self, session: Session, endpoint_id: int, endpoint_name: str) -> None:
        audit = AuditService(session)
        audit.log_event(
            module="cdn",
            action="health_recovered",
            actor=AuditActor(type="system"),
            target=AuditTarget(type="cdn_endpoint", id=str(endpoint_id), name=endpoint_name),
            message="节点恢复为健康状态",
        )
        session.commit()
        logger.info("CDN endpoint %s recovered", endpoint_name)


def should_enable_monitor(*, enabled: bool, environment: str) -> bool:
    if not enabled:
        return False
    if environment.strip().lower() == "test":
        return False
    if os.getenv("PYTEST_CURRENT_TEST"):
        return False
    return True

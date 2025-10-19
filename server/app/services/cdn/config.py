from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.settings import get_settings
from app.services.audit import AuditActor, AuditService


@dataclass(frozen=True)
class CDNMonitorConfig:
    enabled: bool
    interval_seconds: int


class CDNMonitorConfigService:
    def __init__(self, db: Session, *, actor: AuditActor | None = None) -> None:
        self.db = db
        self.actor = actor or AuditActor(type="system")

    def get_config(self) -> CDNMonitorConfig:
        settings = get_settings()
        return CDNMonitorConfig(
            enabled=bool(settings.cdn_health_monitor_enabled),
            interval_seconds=int(settings.cdn_health_monitor_interval_seconds or 0),
        )

    def update_config(self, *, enabled: bool, interval_seconds: int) -> CDNMonitorConfig:
        sanitized_interval = max(30, min(interval_seconds, 3600))
        settings = get_settings()
        settings.cdn_health_monitor_enabled = enabled
        settings.cdn_health_monitor_interval_seconds = sanitized_interval

        self._persist_env(enabled=enabled, interval_seconds=sanitized_interval)

        audit_service = AuditService(self.db)
        audit_service.log_event(
            module="cdn",
            action="health_monitor_config",
            actor=self.actor,
            message="更新 CDN 巡检配置",
            payload={
                "enabled": enabled,
                "interval_seconds": sanitized_interval,
            },
        )
        self.db.commit()

        return CDNMonitorConfig(enabled=enabled, interval_seconds=sanitized_interval)

    def _persist_env(self, *, enabled: bool, interval_seconds: int) -> bool:
        if os.getenv("PYTEST_CURRENT_TEST"):
            return False
        env_path = Path(".env")
        if not env_path.exists():
            return False

        entries = {
            "VMP_CDN_HEALTH_MONITOR_ENABLED": "true" if enabled else "false",
            "VMP_CDN_HEALTH_MONITOR_INTERVAL": str(interval_seconds),
        }

        lines = env_path.read_text(encoding="utf-8").splitlines()
        for key, value in entries.items():
            new_line = f"{key}={value}"
            replaced = False
            for idx, line in enumerate(lines):
                if line.startswith(f"{key}="):
                    lines[idx] = new_line
                    replaced = True
                    break
            if not replaced:
                lines.append(new_line)

        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return True

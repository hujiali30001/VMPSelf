from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import admin
from app.api.routes import router
from app.core.settings import get_settings
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.middleware.access_control import AccessControlMiddleware
from app.middleware.cdn_guard import CDNGuardMiddleware
from app.services.access_control import AccessControlService
from app.services.cdn import CDNHealthMonitor, should_enable_monitor

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        AccessControlService(session).refresh_settings()
    app.state.cdn_health_monitor = None
    health_monitor: Optional[CDNHealthMonitor] = None
    if should_enable_monitor(
        enabled=settings.cdn_health_monitor_enabled,
        environment=settings.environment,
    ):
        health_monitor = CDNHealthMonitor(
            session_factory=SessionLocal,
            interval_seconds=settings.cdn_health_monitor_interval_seconds,
        )
        health_monitor.start()
        app.state.cdn_health_monitor = health_monitor
    yield
    if health_monitor:
        health_monitor.stop()
    app.state.cdn_health_monitor = None


app = FastAPI(title=settings.app_name, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _cdn_whitelist_provider() -> list[str]:
    combined: list[str] = []
    if settings.cdn_ip_whitelist:
        combined.extend(settings.cdn_ip_whitelist)
    if settings.cdn_ip_manual_whitelist:
        combined.extend(settings.cdn_ip_manual_whitelist)
    return combined


def _cdn_blacklist_provider() -> list[str]:
    return list(settings.cdn_ip_blacklist or [])


def _core_whitelist_provider() -> list[str]:
    return list(settings.core_ip_whitelist or [])


def _core_blacklist_provider() -> list[str]:
    return list(settings.core_ip_blacklist or [])

if settings.cdn_enforced and settings.cdn_token:
    app.add_middleware(
        CDNGuardMiddleware,
        header_name=settings.cdn_header_name,
        shared_token=settings.cdn_token,
        allow_paths=settings.cdn_exempt_paths,
        ip_header=settings.cdn_ip_header,
        dynamic_whitelist=_cdn_whitelist_provider,
        dynamic_blacklist=_cdn_blacklist_provider,
    )

app.add_middleware(
    AccessControlMiddleware,
    allow_paths=settings.core_exempt_paths,
    ip_header=(settings.core_ip_header or None),
    dynamic_whitelist=_core_whitelist_provider,
    dynamic_blacklist=_core_blacklist_provider,
)

app.include_router(router, prefix="/api/v1")
app.include_router(admin.router, prefix="/admin")

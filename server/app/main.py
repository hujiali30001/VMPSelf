from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import admin
from app.api.routes import router
from app.core.settings import get_settings
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.middleware.cdn_guard import CDNGuardMiddleware
from app.services.cdn import CDNHealthMonitor

settings = get_settings()


def _should_start_health_monitor() -> bool:
    if not settings.cdn_health_monitor_enabled:
        return False
    if settings.environment.lower() == "test":
        return False
    if os.getenv("PYTEST_CURRENT_TEST"):
        return False
    return True


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    health_monitor: Optional[CDNHealthMonitor] = None
    if _should_start_health_monitor():
        health_monitor = CDNHealthMonitor(
            session_factory=SessionLocal,
            interval_seconds=settings.cdn_health_monitor_interval_seconds,
        )
        health_monitor.start()
    yield
    if health_monitor:
        health_monitor.stop()


app = FastAPI(title=settings.app_name, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if settings.cdn_enforced and settings.cdn_token:
    app.add_middleware(
        CDNGuardMiddleware,
        header_name=settings.cdn_header_name,
        shared_token=settings.cdn_token,
        allow_paths=settings.cdn_exempt_paths,
        ip_header=settings.cdn_ip_header,
        ip_whitelist=settings.cdn_ip_whitelist,
    )

app.include_router(router, prefix="/api/v1")
app.include_router(admin.router, prefix="/admin")

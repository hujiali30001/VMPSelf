from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.settings import get_settings
from app.db.base import Base
from app.db.session import engine
from app.middleware.cdn_guard import CDNGuardMiddleware

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


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

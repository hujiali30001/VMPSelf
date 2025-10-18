from __future__ import annotations

from fastapi import APIRouter

from . import cdn, dashboard, license_types, licenses, settings, software, users
from .api import router as api_router

router = APIRouter()

router.include_router(dashboard.router)
router.include_router(licenses.router)
router.include_router(license_types.router)
router.include_router(users.router)
router.include_router(software.router)
router.include_router(cdn.router)
router.include_router(settings.router)
router.include_router(api_router, tags=["admin-api"])

__all__ = ["router"]

from __future__ import annotations

from fastapi import APIRouter

from . import health, licenses, software, users

router = APIRouter()
router.include_router(users.router)
router.include_router(licenses.router)
router.include_router(software.router)
router.include_router(health.router)

__all__ = ["router"]

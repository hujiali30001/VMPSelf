from __future__ import annotations

from fastapi import APIRouter

from . import license_types, licenses, users

router = APIRouter(prefix="/api")

router.include_router(users.router, tags=["admin-api-users"])
router.include_router(license_types.router, tags=["admin-api-license-types"])
router.include_router(licenses.router, tags=["admin-api-licenses"])

__all__ = ["router"]

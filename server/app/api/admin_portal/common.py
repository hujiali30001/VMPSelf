from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.admin_portal.common_components.auth import (
    AdminPrincipal,
    basic_auth,
    build_audit_actor,
    require_admin,
    require_permission,
)
from app.api.admin_portal.common_components.constants import (
    CDN_STATUS_LABELS,
    CDN_TASK_STATUS_LABELS,
    DEFAULT_NAV_ITEMS,
    NAV_PERMISSION_REQUIREMENTS,
    SOFTWARE_PACKAGE_STATUS_LABELS,
    SOFTWARE_SLOT_STATUS_LABELS,
    STATUS_LABELS,
    settings,
    templates,
)
from app.api.admin_portal.common_components.contexts import (
    _base_context,
    _build_license_detail_context,
    _build_user_detail_context,
)
from app.api.admin_portal.common_components.serializers import (
    _serialize_batch,
    _serialize_card_type,
    _serialize_license,
    _serialize_user,
)
from app.db import License, models
from app.services.accounts import AdminUserService
from app.services.audit import AuditService
from app.services.licensing import LicenseService

DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100


def _sanitize_return_path(return_to: Optional[str], fallback: str = "/admin/licenses") -> str:
    if not return_to:
        return fallback
    if not return_to.startswith("/"):
        return fallback
    if not return_to.startswith("/admin"):
        return fallback
    return return_to


def _build_list_query(
    status: str,
    page: int,
    page_size: int,
    q: Optional[str],
    message: Optional[str] = None,
    type_code: Optional[str] = None,
) -> str:
    params: dict[str, str] = {
        "status": status,
        "page": str(page),
        "page_size": str(page_size),
    }
    if q:
        params["q"] = q
    if type_code:
        params["type_code"] = type_code
    if message:
        params["message"] = message
    return urlencode(params)


def _append_message(path: str, message: str) -> str:
    parsed = urlparse(path)
    query_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query_params["message"] = message
    new_query = urlencode(query_params)
    return urlunparse(parsed._replace(query=new_query))


def _get_license_or_404(db: Session, card_code: str) -> License:
    license_obj = db.scalar(select(License).where(License.card_code == card_code))
    if not license_obj:
        raise HTTPException(status_code=404, detail="license_not_found")
    return license_obj


def _get_user_or_404(db: Session, user_id: int) -> models.User:
    user = db.get(models.User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user_not_found")
    return user


_build_audit_actor = build_audit_actor


def _license_service(db: Session, principal: Optional[AdminPrincipal]) -> LicenseService:
    return LicenseService(db, actor=_build_audit_actor(principal))


def _admin_user_service(db: Session, principal: Optional[AdminPrincipal]) -> AdminUserService:
    return AdminUserService(db, actor=_build_audit_actor(principal))


def _audit_service(db: Session) -> AuditService:
    return AuditService(db)


def _sanitize_optional_str(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed or None


def _parse_filter_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _format_datetime_input(value: Optional[datetime], original: Optional[str]) -> Optional[str]:
    if original:
        return original
    if not value:
        return None
    localized = value.astimezone(timezone.utc)
    localized = localized.replace(second=0, microsecond=0)
    return localized.strftime("%Y-%m-%dT%H:%M")


__all__ = [
    "AdminPrincipal",
    "STATUS_LABELS",
    "CDN_STATUS_LABELS",
    "CDN_TASK_STATUS_LABELS",
    "SOFTWARE_SLOT_STATUS_LABELS",
    "SOFTWARE_PACKAGE_STATUS_LABELS",
    "DEFAULT_NAV_ITEMS",
    "NAV_PERMISSION_REQUIREMENTS",
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "_base_context",
    "_serialize_user",
    "_serialize_card_type",
    "_serialize_license",
    "_serialize_batch",
    "_sanitize_return_path",
    "_build_list_query",
    "_append_message",
    "_get_license_or_404",
    "_build_license_detail_context",
    "_get_user_or_404",
    "_build_user_detail_context",
    "_sanitize_optional_str",
    "_parse_filter_datetime",
    "_format_datetime_input",
    "require_admin",
    "require_permission",
    "_license_service",
    "_admin_user_service",
    "_audit_service",
    "templates",
    "settings",
    "basic_auth",
]

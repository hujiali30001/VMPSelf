from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Request
from sqlalchemy.orm import Session

from app.db import License, models
from app.services.licensing import LicenseService, SoftwareService

from .auth import AdminPrincipal
from .constants import (
    DEFAULT_NAV_ITEMS,
    NAV_PERMISSION_REQUIREMENTS,
    STATUS_LABELS,
    settings,
)


def _base_context(request: Request, **extra: Any) -> dict[str, Any]:
    nav_items = extra.pop("nav_items", None)
    admin_identity = getattr(request.state, "admin_identity", None)
    principal: Optional[AdminPrincipal] = getattr(request.state, "admin_principal", None)
    context: dict[str, Any] = {
        "request": request,
        "nav_items": nav_items if nav_items is not None else [item.copy() for item in DEFAULT_NAV_ITEMS],
        "admin_identity": admin_identity if admin_identity else {"name": settings.admin_username},
        "admin_version": "v1",
        "page_description": extra.get("page_description"),
    }
    if principal and context["nav_items"]:
        filtered_nav: list[dict[str, str]] = []
        for item in context["nav_items"]:
            requirement = NAV_PERMISSION_REQUIREMENTS.get(item.get("code", ""))
            if not requirement:
                filtered_nav.append(item)
                continue
            module_code, action_code = requirement
            if principal.has_permission(module_code, action_code):
                filtered_nav.append(item)
        context["nav_items"] = filtered_nav
    context.update(extra)
    return context


def _build_license_detail_context(
    request: Request,
    license_obj: License,
    db: Session,
    message: Optional[str] = None,
    offline_result: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    latest_seen = None
    if license_obj.activations:
        latest_seen = max(
            (activation.last_seen or activation.activated_at for activation in license_obj.activations),
            default=None,
        )

    service = LicenseService(db)
    audit_logs = service.get_audit_logs(license_obj, limit=100)
    activations = sorted(
        license_obj.activations,
        key=lambda a: (a.last_seen or a.activated_at or datetime.fromtimestamp(0, timezone.utc)),
        reverse=True,
    )

    now = datetime.now(timezone.utc)
    expires_in_days = None
    if license_obj.expire_at:
        expire_at = license_obj.expire_at
        if expire_at.tzinfo is None:
            expire_at = expire_at.replace(tzinfo=timezone.utc)
        expires_in_days = (expire_at - now).days

    return_to = request.url.path
    if request.url.query:
        return_to += f"?{request.url.query}"

    return _base_context(
        request,
        license=license_obj,
        registered_user=license_obj.user,
        latest_seen=latest_seen,
        activations=activations,
        audit_logs=audit_logs,
        message=message,
        status_labels=STATUS_LABELS,
        expires_in_days=expires_in_days,
        offline_result=offline_result,
        return_to=return_to,
        page_title="卡密详情",
        page_subtitle="追踪授权变化，管理绑定用户与设备指纹。",
        page_description="追踪授权变化，管理绑定用户与设备指纹。",
        active_page="licenses",
    )


def _build_user_detail_context(
    request: Request,
    user: models.User,
    db: Session,
    message: Optional[str] = None,
) -> dict[str, Any]:
    license_obj = user.license
    service = LicenseService(db)
    software_slots = SoftwareService(db).list_slots()

    audit_logs = []
    activations = []
    latest_seen = None
    expires_in_days = None

    if license_obj:
        if license_obj.activations:
            activations = sorted(
                license_obj.activations,
                key=lambda a: (a.last_seen or a.activated_at or datetime.fromtimestamp(0, timezone.utc)),
                reverse=True,
            )
            latest_seen = max(
                (activation.last_seen or activation.activated_at for activation in license_obj.activations),
                default=None,
            )
        audit_logs = service.get_audit_logs(license_obj, limit=50)

        if license_obj.expire_at:
            expire_at = license_obj.expire_at
            if expire_at.tzinfo is None:
                expire_at = expire_at.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            expires_in_days = (expire_at - now).days

    return_to = request.url.path
    if request.url.query:
        return_to += f"?{request.url.query}"

    return _base_context(
        request,
        user_obj=user,
        license=license_obj,
        activations=activations,
        audit_logs=audit_logs,
        latest_seen=latest_seen,
        expires_in_days=expires_in_days,
        message=message,
        status_labels=STATUS_LABELS,
        return_to=return_to,
        page_title="用户详情",
        page_subtitle="管理账号信息、关联卡密与安全操作。",
        page_description="管理账号信息、关联卡密与安全操作。",
        active_page="users",
        software_slots=software_slots,
        default_slot_code=software_slots[0].code if software_slots else "",
    )


__all__ = [
    "_base_context",
    "_build_license_detail_context",
    "_build_user_detail_context",
]

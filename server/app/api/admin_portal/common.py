from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from app.api.deps import get_db
from app.core.settings import get_settings
from app.db import (
    CDNEndpointStatus,
    CDNTaskStatus,
    CDNTaskType,
    License,
    LicenseStatus,
    SoftwarePackageStatus,
    SoftwareSlotStatus,
    models,
)
from app.services.admin_user_service import AdminUserService
from app.services.audit_service import AuditActor, AuditService
from app.services.license_service import LicenseService
from app.services.software_service import SoftwareService

settings = get_settings()
basic_auth = HTTPBasic()
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent.parent / "templates"))

STATUS_LABELS = {
    LicenseStatus.UNUSED.value: "未使用",
    LicenseStatus.ACTIVE.value: "已激活",
    LicenseStatus.REVOKED.value: "已撤销",
    LicenseStatus.EXPIRED.value: "已过期",
}

CDN_STATUS_LABELS = {
    CDNEndpointStatus.ACTIVE.value: "活跃",
    CDNEndpointStatus.PAUSED.value: "已暂停",
    CDNEndpointStatus.ERROR.value: "异常",
}

CDN_TASK_STATUS_LABELS = {
    CDNTaskStatus.PENDING.value: "排队中",
    CDNTaskStatus.COMPLETED.value: "已完成",
    CDNTaskStatus.FAILED.value: "失败",
}

SOFTWARE_SLOT_STATUS_LABELS = {
    SoftwareSlotStatus.ACTIVE.value: "上线中",
    SoftwareSlotStatus.PAUSED.value: "暂停",
}

SOFTWARE_PACKAGE_STATUS_LABELS = {
    SoftwarePackageStatus.DRAFT.value: "草稿",
    SoftwarePackageStatus.ACTIVE.value: "已上线",
    SoftwarePackageStatus.RETIRED.value: "已下线",
}

DEFAULT_NAV_ITEMS: tuple[dict[str, str], ...] = (
    {"code": "dashboard", "label": "总览", "href": "/admin"},
    {"code": "licenses", "label": "卡密列表", "href": "/admin/licenses"},
    {"code": "license-types", "label": "卡密类型", "href": "/admin/license-types"},
    {"code": "users", "label": "用户管理", "href": "/admin/users"},
    {"code": "software", "label": "软件位", "href": "/admin/software"},
    {"code": "cdn", "label": "CDN 管理", "href": "/admin/cdn"},
    {"code": "settings", "label": "系统设置", "href": "/admin/settings"},
)

NAV_PERMISSION_REQUIREMENTS: dict[str, tuple[str, str]] = {
    "dashboard": ("dashboard", "view"),
    "licenses": ("licenses", "view"),
    "license-types": ("license-types", "view"),
    "users": ("users", "view"),
    "software": ("software", "view"),
    "cdn": ("cdn", "view"),
    "settings": ("settings", "view"),
}


@dataclass(frozen=True)
class AdminPrincipal:
    id: Optional[int]
    username: str
    role_code: str
    role_display: str
    permissions: FrozenSet[tuple[str, str]]

    def has_permission(self, module: str, action: str) -> bool:
        if self.role_code == "superadmin":
            return True
        module_key = (module or "").strip().lower()
        action_key = (action or "").strip().lower()
        if not module_key or not action_key:
            return False
        if (module_key, action_key) in self.permissions:
            return True
        if (module_key, "*") in self.permissions:
            return True
        if ("*", action_key) in self.permissions:
            return True
        if ("*", "*") in self.permissions:
            return True
        return False


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


def _serialize_user(user: Optional[models.User]) -> Optional[dict[str, Any]]:
    if not user:
        return None
    license_obj = user.license
    return {
        "id": user.id,
        "username": user.username,
        "created_at": user.created_at,
        "card_code": license_obj.card_code if license_obj else None,
        "license_status": license_obj.status if license_obj else None,
        "slot_code": license_obj.software_slot.code if (license_obj and license_obj.software_slot) else None,
    }


def _serialize_card_type(card_type: Optional[models.LicenseCardType]) -> Optional[dict[str, Any]]:
    if not card_type:
        return None
    return {
        "id": card_type.id,
        "code": card_type.code,
        "display_name": card_type.display_name,
        "default_duration_days": card_type.default_duration_days,
        "card_prefix": card_type.card_prefix,
        "description": card_type.description,
        "color": card_type.color,
        "is_active": card_type.is_active,
        "sort_order": card_type.sort_order,
        "created_at": card_type.created_at,
        "updated_at": card_type.updated_at,
    }


def _serialize_batch(batch: Optional[models.LicenseBatch]) -> Optional[dict[str, Any]]:
    if not batch:
        return None
    return {
        "id": batch.id,
        "batch_code": batch.batch_code,
        "quantity": batch.quantity,
        "created_at": batch.created_at,
        "created_by": batch.created_by,
        "type_code": batch.card_type.code if batch.card_type else None,
        "metadata": getattr(batch, "metadata_json", None),
    }


def _serialize_license(license_obj: License) -> dict[str, Any]:
    return {
        "id": license_obj.id,
        "card_code": license_obj.card_code,
        "secret": license_obj.secret,
        "status": license_obj.status,
        "bound_fingerprint": license_obj.bound_fingerprint,
        "expire_at": license_obj.expire_at,
        "created_at": license_obj.created_at,
        "updated_at": license_obj.updated_at,
        "user": _serialize_user(license_obj.user),
        "card_type": _serialize_card_type(getattr(license_obj, "card_type", None)),
        "card_prefix": license_obj.card_prefix,
        "custom_duration_days": license_obj.custom_duration_days,
        "slot_code": license_obj.software_slot.code if license_obj.software_slot else None,
        "batch_id": license_obj.batch.id if license_obj.batch else None,
        "batch_code": license_obj.batch.batch_code if license_obj.batch else None,
        "notes": license_obj.notes,
        "batch": _serialize_batch(license_obj.batch) if license_obj.batch else None,
    }


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


def require_admin(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(basic_auth),
    db: Session = Depends(get_db),
) -> AdminPrincipal:
    admin_service = AdminUserService(db)
    admin = admin_service.verify_credentials(credentials.username, credentials.password)
    if admin:
        permissions = frozenset((perm.module, perm.action) for perm in admin.role.permissions)
        principal = AdminPrincipal(
            id=admin.id,
            username=admin.username,
            role_code=admin.role.code,
            role_display=admin.role.display_name,
            permissions=permissions,
        )
        request.state.admin_identity = {
            "id": admin.id,
            "name": admin.username,
            "role": admin.role.code,
            "role_display": admin.role.display_name,
            "last_login_at": admin.last_login_at,
            "permissions": list(permissions),
        }
        request.state.admin_principal = principal
        return principal

    username_match = secrets.compare_digest(credentials.username, settings.admin_username)
    password_match = secrets.compare_digest(credentials.password, settings.admin_password)
    if username_match and password_match:
        principal = AdminPrincipal(
            id=None,
            username=settings.admin_username,
            role_code="superadmin",
            role_display="系统超级管理员",
            permissions=frozenset({("*", "*")}),
        )
        request.state.admin_identity = {
            "name": settings.admin_username,
            "role": "superadmin",
            "role_display": "系统超级管理员",
            "permissions": [("*", "*")],
        }
        request.state.admin_principal = principal
        return principal

    raise HTTPException(
        status_code=HTTP_401_UNAUTHORIZED,
        detail="Unauthorized",
        headers={"WWW-Authenticate": "Basic"},
    )


def require_permission(module: str, action: str):
    normalized_module = (module or "").strip().lower()
    normalized_action = (action or "").strip().lower()

    if not normalized_module:
        raise ValueError("module_required")
    if not normalized_action:
        raise ValueError("action_required")

    def _dependency(principal: AdminPrincipal = Depends(require_admin)) -> AdminPrincipal:
        if principal.has_permission(normalized_module, normalized_action):
            return principal
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="forbidden")

    return _dependency


def _build_audit_actor(principal: Optional[AdminPrincipal]) -> AuditActor:
    if not principal:
        return AuditActor()
    actor_type = "superadmin" if principal.role_code == "superadmin" else "admin_user"
    return AuditActor(
        type=actor_type,
        id=principal.id,
        name=principal.username,
        role=principal.role_code,
    )


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

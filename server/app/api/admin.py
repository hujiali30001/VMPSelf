from __future__ import annotations

import csv
import io
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import FrozenSet, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload
from starlette.status import HTTP_303_SEE_OTHER, HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

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
from app.schemas import (
    LicenseAdminResponse,
    LicenseBatchCreateResponse,
    LicenseBatchDetailResponse,
    LicenseBatchListResponse,
    LicenseCardTypeCreateRequest,
    LicenseCardTypeListResponse,
    LicenseCardTypeResponse,
    LicenseCardTypeUpdateRequest,
    LicenseCreateRequest,
    LicenseListResponse,
    LicenseUpdateRequest,
    UserDetailResponse,
    UserListResponse,
    UserUpdateRequest,
)
from app.services.admin_user_service import AdminUserService
from app.services.audit_service import AuditActor, AuditService
from app.services.card_type_service import LicenseCardTypeService
from app.services.cdn_service import CDNService
from app.services.license_service import LicenseService
from app.services.role_service import RoleService
from app.services.software_service import SoftwareService
from app.services.user_service import UserService

router = APIRouter()
dashboard_router = APIRouter()
licenses_router = APIRouter(prefix="/licenses")
license_types_router = APIRouter(prefix="/license-types")
users_router = APIRouter(prefix="/users")
software_router = APIRouter(prefix="/software")
cdn_router = APIRouter(prefix="/cdn")
settings_router = APIRouter(prefix="/settings")
api_router = APIRouter(prefix="/api")
api_users_router = APIRouter(prefix="/users")
api_license_types_router = APIRouter(prefix="/license-types")
api_licenses_router = APIRouter(prefix="/licenses")
settings = get_settings()
basic_auth = HTTPBasic()

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))

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


def _base_context(request: Request, **extra: object) -> dict[str, object]:
    nav_items = extra.pop("nav_items", None)
    admin_identity = getattr(request.state, "admin_identity", None)
    principal: Optional[AdminPrincipal] = getattr(request.state, "admin_principal", None)
    context: dict[str, object] = {
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


def _serialize_user(user: Optional[models.User]) -> Optional[dict[str, object]]:
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


def _serialize_card_type(card_type: Optional[models.LicenseCardType]) -> Optional[dict[str, object]]:
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


def _serialize_license(license_obj: License) -> dict[str, object]:
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


def _serialize_batch(batch: Optional[models.LicenseBatch]) -> Optional[dict[str, object]]:
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


def _build_license_detail_context(
    request: Request,
    license_obj: License,
    db: Session,
    message: Optional[str] = None,
    offline_result: Optional[dict[str, str]] = None,
) -> dict[str, object]:
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


def _get_user_or_404(db: Session, user_id: int) -> models.User:
    user = db.get(models.User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user_not_found")
    return user


def _build_user_detail_context(
    request: Request,
    user: models.User,
    db: Session,
    message: Optional[str] = None,
) -> dict[str, object]:
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


@dashboard_router.get("/")
def dashboard_page(
    request: Request,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("dashboard", "view")),
):
    total_users = db.scalar(select(func.count()).select_from(models.User)) or 0
    total_licenses = db.scalar(select(func.count()).select_from(License)) or 0
    total_card_types = db.scalar(select(func.count()).select_from(models.LicenseCardType)) or 0
    active_card_types = (
        db.scalar(
            select(func.count())
            .select_from(models.LicenseCardType)
            .where(models.LicenseCardType.is_active.is_(True))
        )
        or 0
    )
    total_activations = db.scalar(select(func.count()).select_from(models.Activation)) or 0

    status_rows = db.execute(select(License.status, func.count()).group_by(License.status)).all()
    status_counts = {status: count for status, count in status_rows}
    for status in LicenseStatus:
        status_counts.setdefault(status.value, 0)

    now = datetime.now(timezone.utc)
    upcoming = now + timedelta(days=7)

    recent_users_stmt = (
        select(models.User)
        .options(selectinload(models.User.license))
        .order_by(models.User.created_at.desc())
        .limit(6)
    )
    recent_users = [
        user_data
        for user_data in (_serialize_user(user) for user in db.execute(recent_users_stmt).scalars().all())
        if user_data
    ]

    recent_licenses_stmt = (
        select(License)
        .options(selectinload(License.user), selectinload(License.card_type))
        .order_by(License.created_at.desc())
        .limit(6)
    )
    recent_licenses = [
        license_data
        for license_data in (
            _serialize_license(license_obj)
            for license_obj in db.execute(recent_licenses_stmt).scalars().all()
        )
        if license_data
    ]

    expiring_soon_stmt = (
        select(License)
        .options(selectinload(License.user), selectinload(License.card_type))
        .where(
            License.expire_at.isnot(None),
            License.expire_at > now,
            License.expire_at <= upcoming,
        )
        .order_by(License.expire_at.asc())
        .limit(5)
    )
    expiring_licenses = [
        license_data
        for license_data in (
            _serialize_license(license_obj)
            for license_obj in db.execute(expiring_soon_stmt).scalars().all()
        )
        if license_data
    ]

    overall_stats = [
        {"code": "users", "label": "注册用户", "value": total_users},
        {"code": "licenses", "label": "卡密总量", "value": total_licenses},
        {
            "code": "active-licenses",
            "label": "激活中的卡密",
            "value": status_counts.get(LicenseStatus.ACTIVE.value, 0),
        },
        {"code": "activations", "label": "激活设备", "value": total_activations},
        {
            "code": "card-types",
            "label": "启用卡密类型",
            "value": active_card_types,
            "meta": f"共 {total_card_types} 种",
        },
    ]

    status_summary = [
        {
            "code": status.value,
            "label": STATUS_LABELS.get(status.value, status.value),
            "count": status_counts.get(status.value, 0),
        }
        for status in LicenseStatus
    ]

    module_cards = [
        {
            "code": "users",
            "label": "用户中心",
            "description": "管理注册账号、关联卡密与安全操作。",
            "href": "/admin/users",
            "ready": True,
        },
        {
            "code": "licenses",
            "label": "卡密管理",
            "description": "创建卡密、筛选状态并快速跳转详情页。",
            "href": "/admin/licenses",
            "ready": True,
        },
        {
            "code": "license-types",
            "label": "卡密类型",
            "description": "维护卡密模板、默认时长与前缀策略。",
            "href": "/admin/license-types",
            "ready": True,
        },
        {
            "code": "cdn",
            "label": "CDN 管理",
            "description": "配置源站防护、共享密钥与 IP 白名单。",
            "href": "/admin/cdn",
            "ready": False,
            "badge": "规划中",
        },
        {
            "code": "software",
            "label": "软件位",
            "description": "上传保护壳、分配发布渠道与配额。",
            "href": "/admin/software",
            "ready": False,
            "badge": "规划中",
        },
        {
            "code": "settings",
            "label": "系统设置",
            "description": "调整后台安全策略、审计与管理员账号。",
            "href": "/admin/settings",
            "ready": False,
            "badge": "规划中",
        },
    ]

    context = _base_context(
        request,
        page_title="控制台总览",
        page_subtitle="统一入口集中管理授权服务核心模块。",
        page_description="综合查看用户、卡密与即将过期的关键指标。",
        active_page="dashboard",
        stats=overall_stats,
        status_summary=status_summary,
        module_cards=module_cards,
        recent_users=recent_users,
        recent_licenses=recent_licenses,
        expiring_licenses=expiring_licenses,
        status_counts=status_counts,
        total_card_types=total_card_types,
        timeframe_days=7,
        now=now,
        status_labels=STATUS_LABELS,
    )

    return templates.TemplateResponse(
        request,
        "admin/dashboard/index.html",
        context,
    )


@api_users_router.get("/", response_model=UserListResponse)
def api_list_users(
    offset: int = 0,
    limit: int = 50,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("users", "view")),
):
    offset = max(offset, 0)
    limit = max(1, min(limit, 200))
    search_query = search.strip() if search else None

    service = UserService(db)
    items = service.list_users(offset=offset, limit=limit, search=search_query)

    total_stmt = select(func.count()).select_from(models.User)
    if search_query:
        total_stmt = total_stmt.where(models.User.username.ilike(f"%{search_query}%"))
    total = db.scalar(total_stmt) or 0

    return {
        "items": [_serialize_user(user) for user in items],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@api_users_router.get("/{user_id}", response_model=UserDetailResponse)
def api_get_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("users", "view")),
):
    user = UserService(db).get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user_not_found")
    serialized = _serialize_user(user)
    assert serialized is not None
    return serialized


@api_users_router.patch("/{user_id}", response_model=UserDetailResponse)
def api_update_user(
    user_id: int,
    payload: UserUpdateRequest,
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("users", "manage")),
):
    if (
        payload.username is None
        and payload.password is None
        and payload.card_code is None
        and payload.slot_code is None
    ):
        raise HTTPException(status_code=400, detail="no_fields_provided")

    service = UserService(db, actor=_build_audit_actor(principal))
    try:
        user = service.update_user(
            user_id,
            username=payload.username,
            password=payload.password,
            card_code=payload.card_code,
            slot_code=payload.slot_code,
        )
    except ValueError as exc:
        message = str(exc)
        if message in {
            "user_not_found",
            "username_too_short",
            "password_too_short",
            "card_code_required",
            "license_not_found",
            "license_already_bound",
            "license_revoked",
            "username_taken",
            "user_update_failed",
            "slot_code_required",
            "slot_not_found",
            "slot_mismatch",
            "license_slot_unset",
        }:
            status_code = 404 if message == "user_not_found" else 400
            raise HTTPException(status_code=status_code, detail=message)
        raise

    serialized = _serialize_user(user)
    assert serialized is not None
    return serialized


@api_users_router.delete("/{user_id}", status_code=204)
def api_delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("users", "manage")),
):
    if not UserService(db, actor=_build_audit_actor(principal)).delete_user(user_id):
        raise HTTPException(status_code=404, detail="user_not_found")
    return Response(status_code=204)


@api_license_types_router.get("/", response_model=LicenseCardTypeListResponse)
def api_list_license_types(
    include_inactive: bool = True,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("license-types", "view")),
):
    service = LicenseCardTypeService(db)
    items = service.list_types(include_inactive=include_inactive)
    return {
        "items": [_serialize_card_type(item) for item in items if item],
        "total": len(items),
    }


@api_license_types_router.post("/", response_model=LicenseCardTypeResponse, status_code=201)
def api_create_license_type(
    payload: LicenseCardTypeCreateRequest,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("license-types", "manage")),
):
    service = LicenseCardTypeService(db)
    try:
        card_type = service.create_type(**payload.dict())
    except ValueError as exc:
        message = str(exc)
        if message in {
            "card_type_exists",
            "code_blank",
            "code_invalid",
            "duration_invalid",
            "duration_too_large",
            "prefix_too_long",
            "prefix_invalid",
            "color_invalid",
        }:
            raise HTTPException(status_code=400, detail=message)
        raise
    serialized = _serialize_card_type(card_type)
    assert serialized is not None
    return serialized


@api_license_types_router.patch("/{type_id}", response_model=LicenseCardTypeResponse)
def api_update_license_type(
    type_id: int,
    payload: LicenseCardTypeUpdateRequest,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("license-types", "manage")),
):
    updates = payload.dict(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="no_fields_provided")

    service = LicenseCardTypeService(db)
    try:
        card_type = service.update_type(type_id, **updates)
    except ValueError as exc:
        message = str(exc)
        if message in {
            "card_type_not_found",
        }:
            raise HTTPException(status_code=404, detail=message)
        if message in {
            "display_name_blank",
            "duration_invalid",
            "duration_too_large",
            "prefix_too_long",
            "prefix_invalid",
            "color_invalid",
        }:
            raise HTTPException(status_code=400, detail=message)
        raise

    serialized = _serialize_card_type(card_type)
    assert serialized is not None
    return serialized


@api_license_types_router.delete("/{type_id}", status_code=204)
def api_delete_license_type(
    type_id: int,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("license-types", "manage")),
):
    service = LicenseCardTypeService(db)
    try:
        deleted = service.delete_type(type_id)
    except ValueError as exc:
        if str(exc) == "card_type_in_use":
            raise HTTPException(status_code=400, detail="card_type_in_use")
        raise

    if not deleted:
        raise HTTPException(status_code=404, detail="card_type_not_found")
    return Response(status_code=204)


@api_licenses_router.get("/", response_model=LicenseListResponse)
def api_list_licenses(
    status: str = "all",
    offset: int = 0,
    limit: int = 50,
    search: Optional[str] = None,
    type_code: Optional[str] = None,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("licenses", "view")),
):
    offset = max(offset, 0)
    limit = max(1, min(limit, 200))
    search_query = search.strip() if search else None
    type_filter = type_code.strip() if type_code else None

    service = LicenseService(db)
    items = service.list_licenses(
        status=status,
        search=search_query,
        type_code=type_filter,
        offset=offset,
        limit=limit,
    )

    total_stmt = select(func.count()).select_from(License)
    if status and status != "all":
        total_stmt = total_stmt.where(License.status == status)
    if search_query:
        total_stmt = total_stmt.where(License.card_code.ilike(f"%{search_query}%"))
    if type_filter:
        total_stmt = (
            total_stmt.join_from(
                License,
                models.LicenseCardType,
                License.card_type_id == models.LicenseCardType.id,
            )
            .where(models.LicenseCardType.code == type_filter)
        )
    total = db.scalar(total_stmt) or 0

    return {
        "items": [_serialize_license(license_obj) for license_obj in items],
        "total": total,
        "offset": offset,
        "limit": limit,
    }

@api_licenses_router.get("/batches", response_model=LicenseBatchListResponse)
def api_list_license_batches(
    offset: int = Query(0, ge=0, le=10_000),
    limit: int = Query(20, ge=1, le=200),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("licenses", "view")),
):
    service = LicenseService(db)
    items = service.list_batches(offset=offset, limit=limit)
    total = db.scalar(select(func.count()).select_from(models.LicenseBatch)) or 0
    return {
        "items": [_serialize_batch(batch) for batch in items if batch],
        "total": total,
        "offset": offset,
        "limit": limit,
    }

@api_licenses_router.get("/batches/{batch_id}", response_model=LicenseBatchDetailResponse)
def api_get_license_batch(
    batch_id: int,
    include_licenses: bool = Query(True),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("licenses", "view")),
):
    service = LicenseService(db)
    batch = service.get_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="batch_not_found")
    licenses = batch.licenses if include_licenses else []
    return {
        "batch": _serialize_batch(batch),
        "licenses": [_serialize_license(license_obj) for license_obj in licenses],
    }

@api_licenses_router.get("/batches/by-code/{batch_code}", response_model=LicenseBatchDetailResponse)
def api_get_license_batch_by_code(
    batch_code: str,
    include_licenses: bool = Query(True),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("licenses", "view")),
):
    service = LicenseService(db)
    batch = service.get_batch_by_code(batch_code)
    if not batch:
        raise HTTPException(status_code=404, detail="batch_not_found")
    licenses = batch.licenses if include_licenses else []
    return {
        "batch": _serialize_batch(batch),
        "licenses": [_serialize_license(license_obj) for license_obj in licenses],
    }

@api_licenses_router.post("/", response_model=LicenseBatchCreateResponse, status_code=201)
def api_create_license(
    payload: LicenseCreateRequest,
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("licenses", "manage")),
):
    service = _license_service(db, principal)
    try:
        licenses, batch = service.create_licenses(
            type_code=payload.type_code,
            card_code=payload.card_code,
            quantity=payload.quantity,
            custom_prefix=payload.custom_prefix,
            ttl_days=payload.ttl_days,
            custom_ttl_days=payload.custom_ttl_days,
            slot_code=payload.slot_code,
        )
    except ValueError as exc:
        message = str(exc)
        if message in {
            "card_type_not_found",
            "card_type_disabled",
            "card_code_exists",
            "card_code_blank",
            "card_code_too_long",
            "card_code_requires_single_quantity",
            "quantity_invalid",
            "quantity_too_large",
            "custom_ttl_invalid",
            "ttl_invalid",
            "prefix_invalid",
            "prefix_too_long",
            "slot_code_required",
            "slot_not_found",
        }:
            raise HTTPException(status_code=400, detail=message)
        raise
    except IntegrityError:
        raise HTTPException(status_code=400, detail="card_code_exists")

    return {
        "items": [_serialize_license(obj) for obj in licenses],
        "batch": _serialize_batch(batch),
        "quantity": len(licenses),
    }


@api_licenses_router.get("/{card_code}", response_model=LicenseAdminResponse)
def api_get_license(
    card_code: str,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("licenses", "view")),
):
    license_obj = LicenseService(db).get_license(card_code)
    if not license_obj:
        raise HTTPException(status_code=404, detail="license_not_found")
    return _serialize_license(license_obj)


@api_licenses_router.patch("/{card_code}", response_model=LicenseAdminResponse)
def api_update_license(
    card_code: str,
    payload: LicenseUpdateRequest,
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("licenses", "manage")),
):
    if payload.expire_at is None and payload.status is None and payload.bound_fingerprint is None:
        raise HTTPException(status_code=400, detail="no_fields_provided")

    service = _license_service(db, principal)
    try:
        license_obj = service.update_license(
            card_code,
            expire_at=payload.expire_at,
            status=payload.status,
            bound_fingerprint=payload.bound_fingerprint,
        )
    except ValueError as exc:
        message = str(exc)
        if message in {"license_not_found", "invalid_expiry", "invalid_status"}:
            status_code = 404 if message == "license_not_found" else 400
            raise HTTPException(status_code=status_code, detail=message)
        raise

    return _serialize_license(license_obj)


@api_licenses_router.delete("/{card_code}", status_code=204)
def api_delete_license(
    card_code: str,
    force: bool = False,
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("licenses", "manage")),
):
    service = _license_service(db, principal)
    try:
        success = service.delete_license(card_code, force=force)
    except ValueError as exc:
        if str(exc) == "license_active":
            raise HTTPException(status_code=400, detail="license_active")
        raise

    if not success:
        raise HTTPException(status_code=404, detail="license_not_found")
    return Response(status_code=204)


@license_types_router.get("/")
def license_types_page(
    request: Request,
    edit: Optional[int] = None,
    message: Optional[str] = None,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("license-types", "view")),
):
    service = LicenseCardTypeService(db)
    card_types = service.list_types(include_inactive=True)

    counts = {
        row[0]: row[1]
        for row in db.execute(
            select(models.License.card_type_id, func.count()).group_by(models.License.card_type_id)
        ).all()
    }

    edit_type = None
    if edit:
        edit_type = service.get_by_id(edit)
        if not edit_type:
            message = "未找到指定卡密类型"

    total_active = sum(1 for item in card_types if item.is_active)
    total_inactive = len(card_types) - total_active

    card_type_rows = [
        {
            "type": item,
            "license_count": counts.get(item.id, 0),
        }
        for item in card_types
    ]

    return_to = request.url.path
    if request.url.query:
        return_to += f"?{request.url.query}"

    context = _base_context(
        request,
        card_types=card_type_rows,
        total=len(card_types),
        total_active=total_active,
        total_inactive=total_inactive,
        edit_type=edit_type,
        message=message,
        return_to=return_to,
        page_description="管理卡密类型、前缀与默认策略。",
    )

    return templates.TemplateResponse(
        request,
        "admin/card_types/index.html",
        context,
    )


@license_types_router.post("/create")
def create_license_type_action(
    request: Request,
    code: str = Form(...),
    display_name: str = Form(...),
    default_duration_days: Optional[str] = Form(None),
    card_prefix: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    color: Optional[str] = Form(None),
    sort_order: Optional[str] = Form(None),
    is_active: Optional[str] = Form(None),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("license-types", "manage")),
):
    service = LicenseCardTypeService(db)
    try:
        duration = int(default_duration_days) if default_duration_days else None
    except ValueError:
        duration = None
        message = "默认有效期需要为数字"
        target = _append_message(_sanitize_return_path(return_to, fallback="/admin/license-types"), message)
        return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)

    try:
        order_value = int(sort_order) if sort_order else None
    except ValueError:
        order_value = None
        message = "排序值需要为数字"
        target = _append_message(_sanitize_return_path(return_to, fallback="/admin/license-types"), message)
        return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)

    try:
        service.create_type(
            code=code,
            display_name=display_name,
            default_duration_days=duration,
            card_prefix=card_prefix,
            description=description,
            color=color,
            sort_order=order_value,
            is_active=bool(is_active),
        )
    except ValueError as exc:
        db.rollback()
        message = str(exc)
    else:
        message = f"已创建类型 {code}"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/license-types"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@license_types_router.post("/{type_id}/update")
def update_license_type_action(
    request: Request,
    type_id: int,
    display_name: Optional[str] = Form(None),
    default_duration_days: Optional[str] = Form(None),
    card_prefix: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    color: Optional[str] = Form(None),
    sort_order: Optional[str] = Form(None),
    is_active: Optional[str] = Form(None),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("license-types", "manage")),
):
    service = LicenseCardTypeService(db)

    def _parse_int(value: Optional[str]) -> Optional[int]:
        if value is None or value.strip() == "":
            return None
        return int(value)

    updates: dict[str, object] = {}
    if display_name is not None:
        updates["display_name"] = display_name
    if default_duration_days is not None:
        try:
            updates["default_duration_days"] = _parse_int(default_duration_days)
        except ValueError:
            message = "默认有效期需要为数字"
            target = _append_message(_sanitize_return_path(return_to, fallback="/admin/license-types?edit={type_id}".format(type_id=type_id)), message)
            return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)
    if card_prefix is not None:
        updates["card_prefix"] = card_prefix
    if description is not None:
        updates["description"] = description
    if color is not None:
        updates["color"] = color
    if sort_order is not None:
        try:
            updates["sort_order"] = _parse_int(sort_order)
        except ValueError:
            message = "排序值需要为数字"
            target = _append_message(_sanitize_return_path(return_to, fallback="/admin/license-types?edit={type_id}".format(type_id=type_id)), message)
            return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)
    updates["is_active"] = is_active is not None

    try:
        service.update_type(type_id, **updates)
    except ValueError as exc:
        db.rollback()
        message = str(exc)
    else:
        message = "类型信息已更新"

    target = _append_message(
        _sanitize_return_path(return_to, fallback="/admin/license-types"),
        message,
    )
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@license_types_router.post("/{type_id}/toggle")
def toggle_license_type_action(
    request: Request,
    type_id: int,
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("license-types", "manage")),
):
    service = LicenseCardTypeService(db)
    card_type = service.get_by_id(type_id)
    if not card_type:
        message = "未找到指定卡密类型"
    else:
        try:
            updated = service.update_type(type_id, is_active=not card_type.is_active)
        except ValueError as exc:
            db.rollback()
            message = str(exc)
        else:
            message = "已启用" if updated.is_active else "已停用"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/license-types"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@license_types_router.post("/{type_id}/delete")
def delete_license_type_action(
    request: Request,
    type_id: int,
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("license-types", "manage")),
):
    service = LicenseCardTypeService(db)
    try:
        deleted = service.delete_type(type_id)
    except ValueError as exc:
        db.rollback()
        message = str(exc)
    else:
        message = "类型已删除" if deleted else "未找到指定卡密类型"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/license-types"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@users_router.get("/")
def users_page(
    request: Request,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    q: Optional[str] = None,
    message: Optional[str] = None,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("users", "view")),
):
    page = max(page, 1)
    page_size = max(1, min(page_size, MAX_PAGE_SIZE))
    search_query = q.strip() if q else None

    total_stmt = select(func.count()).select_from(models.User)
    if search_query:
        total_stmt = total_stmt.where(models.User.username.ilike(f"%{search_query}%"))
    total = db.scalar(total_stmt) or 0

    total_pages = max((total + page_size - 1) // page_size, 1) if total else 1
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * page_size

    service = UserService(db)
    users = service.list_users(offset=offset, limit=page_size, search=search_query)

    user_rows = []
    for user in users:
        license_obj = user.license
        latest_seen = None
        activation_count = 0
        expires_at = None
        if license_obj:
            activation_count = len(license_obj.activations)
            expires_at = license_obj.expire_at
            if license_obj.activations:
                latest_seen = max(
                    (activation.last_seen or activation.activated_at for activation in license_obj.activations),
                    default=None,
                )

        user_rows.append(
            {
                "user": user,
                "license": license_obj,
                "activation_count": activation_count,
                "latest_seen": latest_seen,
                "expires_at": expires_at,
            }
        )

    status_counts = {
        row[0]: row[1]
        for row in db.execute(
            select(models.License.status, func.count())
            .join(models.User, models.User.license_id == models.License.id)
            .group_by(models.License.status)
        ).all()
    }

    has_prev = page > 1
    has_next = page < total_pages
    return_to = request.url.path
    if request.url.query:
        return_to += f"?{request.url.query}"

    software_slots = SoftwareService(db).list_slots()
    default_slot_code = software_slots[0].code if software_slots else ""

    context = _base_context(
        request,
        users=user_rows,
        page=page,
        page_size=page_size,
        query=search_query or "",
        total=total,
        total_pages=total_pages,
        has_prev=has_prev,
        has_next=has_next,
        prev_page=page - 1,
        next_page=page + 1,
        message=message,
        status_labels=STATUS_LABELS,
        status_counts=status_counts,
        return_to=return_to,
        page_title="用户管理",
        page_subtitle="集中查看注册账号、关联卡密与安全状态。",
        page_description="集中查看注册账号、关联卡密与安全状态。",
        active_page="users",
        software_slots=software_slots,
        default_slot_code=default_slot_code,
    )

    return templates.TemplateResponse(
        request,
        "admin/users/index.html",
        context,
    )


@users_router.get("/{user_id}")
def user_detail(
    request: Request,
    user_id: int,
    message: Optional[str] = None,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("users", "view")),
):
    user = _get_user_or_404(db, user_id)
    context = _build_user_detail_context(request, user, db, message=message)
    return templates.TemplateResponse(request, "admin/users/detail.html", context)


@users_router.post("/register")
def register_user_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    card_code: str = Form(...),
    slot_code: str = Form(...),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("users", "manage")),
):
    username = username.strip()
    card_code = card_code.strip()
    slot_code = slot_code.strip().lower()
    message: str

    if password != confirm_password:
        message = "两次输入的密码不一致"
    else:
        service = UserService(db, actor=_build_audit_actor(principal))
        try:
            user = service.register(username, password, card_code, slot_code)
        except ValueError as exc:
            db.rollback()
            error = str(exc)
            error_map = {
                "username_too_short": "用户名至少 3 个字符",
                "password_too_short": "密码至少 8 位",
                "card_code_required": "请填写卡密",
                "slot_code_required": "请选择软件位",
                "slot_not_found": "未找到该软件位",
                "license_not_found": "未找到对应卡密",
                "license_expired": "卡密已过期",
                "license_revoked": "卡密已撤销",
                "license_already_bound": "卡密已绑定其他用户",
                "license_slot_unset": "卡密未绑定软件位，请联系管理员先设置",
                "slot_mismatch": "卡密所属软件位与选择不一致",
                "username_taken": "用户名已存在",
            }
            message = error_map.get(error, f"创建用户失败: {error}")
        else:
            message = f"已创建用户 {user.username}"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/users"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@users_router.post("/{user_id}/profile")
def update_user_profile_action(
    request: Request,
    user_id: int,
    username: Optional[str] = Form(None),
    card_code: Optional[str] = Form(None),
    slot_code: Optional[str] = Form(None),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("users", "manage")),
):
    username = (username or "").strip()
    card_code = (card_code or "").strip()
    slot_code = (slot_code or "").strip().lower()

    updates: dict[str, Optional[str]] = {}
    if username:
        updates["username"] = username
    if card_code:
        updates["card_code"] = card_code
    if slot_code:
        updates["slot_code"] = slot_code

    if not updates:
        message = "请填写需要更新的字段"
    else:
        service = UserService(db, actor=_build_audit_actor(principal))
        try:
            service.update_user(user_id, **updates)
        except ValueError as exc:
            db.rollback()
            error = str(exc)
            error_map = {
                "user_not_found": "未找到用户",
                "username_too_short": "用户名至少 3 个字符",
                "card_code_required": "请填写卡密",
                "license_not_found": "未找到对应卡密",
                "license_already_bound": "卡密已绑定其他用户",
                "license_revoked": "卡密已撤销",
                "license_slot_unset": "卡密未绑定软件位，请先在卡密详情页设置",
                "slot_code_required": "请选择软件位",
                "slot_not_found": "未找到该软件位",
                "slot_mismatch": "卡密所属软件位与选择不一致",
                "username_taken": "用户名已存在",
            }
            message = error_map.get(error, error)
        else:
            message = "用户信息已更新"

    target = _append_message(
        _sanitize_return_path(return_to, fallback=f"/admin/users/{user_id}"),
        message,
    )
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@users_router.post("/{user_id}/password")
def update_user_password_action(
    request: Request,
    user_id: int,
    password: str = Form(...),
    confirm_password: str = Form(...),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("users", "manage")),
):
    if password != confirm_password:
        message = "两次输入的密码不一致"
    else:
        service = UserService(db, actor=_build_audit_actor(principal))
        try:
            service.update_user(user_id, password=password)
        except ValueError as exc:
            db.rollback()
            message = str(exc)
        else:
            message = "密码已更新"

    target = _append_message(
        _sanitize_return_path(return_to, fallback=f"/admin/users/{user_id}"),
        message,
    )
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@users_router.post("/{user_id}/delete")
def delete_user_action(
    request: Request,
    user_id: int,
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("users", "manage")),
):
    service = UserService(db, actor=_build_audit_actor(principal))
    success = service.delete_user(user_id)
    message = "用户已删除" if success else "未找到指定用户"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/users"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)

@licenses_router.get("/")
def licenses_page(
    request: Request,
    status: str = "all",
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    q: Optional[str] = None,
    type_code: Optional[str] = None,
    message: str | None = None,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("licenses", "view")),
):
    page = max(page, 1)
    page_size = max(1, min(page_size, MAX_PAGE_SIZE))
    search_query = q.strip() if q else None
    type_query = type_code.strip() if type_code else None

    card_type_service = LicenseCardTypeService(db)
    card_types = card_type_service.list_types(include_inactive=True)
    active_card_types = [item for item in card_types if item.is_active]

    def apply_filters(stmt, include_type: bool = True):
        if status != "all":
            stmt = stmt.where(License.status == status)
        if search_query:
            stmt = stmt.where(License.card_code.ilike(f"%{search_query}%"))
        if include_type:
            if type_query == "__none__":
                stmt = stmt.where(License.card_type_id.is_(None))
            elif type_query:
                stmt = stmt.join(License.card_type).where(models.LicenseCardType.code == type_query)
        return stmt

    total_stmt = select(func.count()).select_from(License)
    total = db.scalar(apply_filters(total_stmt)) or 0
    total_pages = max((total + page_size - 1) // page_size, 1) if total else 1
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * page_size

    license_stmt = apply_filters(
        select(License)
        .options(
            selectinload(License.activations),
            selectinload(License.user),
            selectinload(License.card_type),
            selectinload(License.software_slot),
        )
        .order_by(License.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )

    license_rows = []
    for license_obj in db.scalars(license_stmt).all():
        latest_seen = None
        if license_obj.activations:
            latest_seen = max(
                (
                    activation.last_seen or activation.activated_at
                    for activation in license_obj.activations
                    if activation.last_seen or activation.activated_at
                ),
                default=None,
            )
        license_rows.append(
            {
                "license": license_obj,
                "latest_seen": latest_seen,
                "activation_count": len(license_obj.activations),
                "user": license_obj.user,
            }
        )

    statuses = [("all", "全部"), *[(s.value, STATUS_LABELS.get(s.value, s.value)) for s in LicenseStatus]]
    status_counts_stmt = select(License.status, func.count()).select_from(License)
    status_counts_stmt = apply_filters(status_counts_stmt)
    status_counts_stmt = status_counts_stmt.group_by(License.status)
    status_counts = {row[0]: row[1] for row in db.execute(status_counts_stmt).all()}

    type_counts_stmt = select(License.card_type_id, func.count()).select_from(License)
    type_counts_stmt = apply_filters(type_counts_stmt, include_type=False)
    type_counts_stmt = type_counts_stmt.group_by(License.card_type_id)
    type_counts = {row[0]: row[1] for row in db.execute(type_counts_stmt).all()}

    selected_card_type = None
    if type_query:
        selected_card_type = next((item for item in card_types if item and item.code == type_query), None)

    def _build_type_link(code: Optional[str]) -> str:
        return f"/admin/licenses?{_build_list_query(status, 1, page_size, search_query, None, code)}"

    type_breakdown: list[dict[str, object]] = []
    type_breakdown.append(
        {
            "code": "",
            "label": "全部类型",
            "count": sum(type_counts.values()),
            "is_active": True,
            "url": _build_type_link(None),
            "is_selected": not type_query,
        }
    )
    type_breakdown.append(
        {
            "code": "__none__",
            "label": "未设置类型",
            "count": type_counts.get(None, 0),
            "is_active": True,
            "url": _build_type_link("__none__"),
            "is_selected": type_query == "__none__",
        }
    )
    for item in card_types:
        type_breakdown.append(
            {
                "code": item.code,
                "label": item.display_name,
                "count": type_counts.get(item.id, 0),
                "is_active": item.is_active,
                "url": _build_type_link(item.code),
                "is_selected": type_query == item.code,
                "type": item,
            }
        )

    selected_type_total = 0
    if type_query == "__none__":
        selected_type_total = type_counts.get(None, 0)
    elif selected_card_type:
        selected_type_total = type_counts.get(selected_card_type.id, 0)
    elif not type_query:
        selected_type_total = sum(type_counts.values())

    type_filter_urls = {entry["code"]: entry["url"] for entry in type_breakdown}

    software_slots = SoftwareService(db).list_slots()
    default_slot_code = software_slots[0].code if software_slots else ""

    context = _base_context(
        request,
        licenses=license_rows,
        status=status,
        page=page,
        page_size=page_size,
        query=search_query or "",
        total=total,
        total_pages=total_pages,
        has_prev=page > 1,
        has_next=page < total_pages,
        prev_page=page - 1,
        next_page=page + 1,
        statuses=statuses,
        status_counts=status_counts,
        message=message,
        status_labels=STATUS_LABELS,
        card_types=card_types,
        active_card_types=active_card_types,
        selected_type_code=type_query or "",
        selected_card_type=selected_card_type,
        type_breakdown=type_breakdown,
        selected_type_total=selected_type_total,
        type_filter_urls=type_filter_urls,
        page_description="集中查看卡密状态、注册用户与激活设备。",
        software_slots=software_slots,
        default_slot_code=default_slot_code,
    )

    return templates.TemplateResponse(
        request,
        "admin/licenses/index.html",
        context,
    )


@licenses_router.get("/batches")
def license_batches_page(
    request: Request,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    message: Optional[str] = None,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("licenses", "view")),
):
    page = max(page, 1)
    page_size = max(1, min(page_size, MAX_PAGE_SIZE))
    offset = (page - 1) * page_size

    service = LicenseService(db)
    batches = service.list_batches(offset=offset, limit=page_size)
    total = db.scalar(select(func.count()).select_from(models.LicenseBatch)) or 0
    total_pages = max((total + page_size - 1) // page_size, 1) if total else 1
    if page > total_pages:
        page = total_pages
        offset = (page - 1) * page_size
        batches = service.list_batches(offset=offset, limit=page_size)

    context = _base_context(
        request,
        page_title="卡密批次",
        page_subtitle="快速浏览批量生成记录并回溯相关卡密",
        page_description="浏览批次生成记录，查看卡密数量与关联类型",
        active_page="licenses",
        batches=batches,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        message=message,
    )
    return templates.TemplateResponse(request, "admin/licenses/batches.html", context)


@licenses_router.get("/batches/{batch_id}")
def license_batch_detail_page(
    request: Request,
    batch_id: int,
    message: Optional[str] = None,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("licenses", "view")),
):
    service = LicenseService(db)
    batch = service.get_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="batch_not_found")

    licenses = sorted(
        batch.licenses,
        key=lambda item: item.created_at or datetime.fromtimestamp(0, timezone.utc),
        reverse=True,
    )

    context = _base_context(
        request,
        batch=batch,
        licenses=licenses,
        page_title=f"批次 {batch.batch_code}",
        page_subtitle="查看批量生成的记录和卡密列表",
        page_description="批次详情",
        active_page="licenses",
        message=message,
        status_labels=STATUS_LABELS,
    )
    return templates.TemplateResponse(request, "admin/licenses/batch_detail.html", context)


@licenses_router.post("/create")
def create_license_action(
    request: Request,
    card_code: Optional[str] = Form(None),
    type_code: Optional[str] = Form(None),
    quantity: Optional[str] = Form("1"),
    custom_prefix: Optional[str] = Form(None),
    ttl_days: Optional[str] = Form(None),
    custom_ttl_days: Optional[str] = Form(None),
    slot_code: str = Form(...),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("licenses", "manage")),
):
    service = _license_service(db, principal)

    def _parse_int(value: Optional[str]) -> Optional[int]:
        if value is None:
            return None
        trimmed = value.strip()
        if trimmed == "":
            return None
        return int(trimmed)

    card_code_value = (card_code or "").strip() or None
    type_value = (type_code or "").strip() or None
    if type_value == "__none__":
        type_value = None
    prefix_value = (custom_prefix or "").strip() or None
    slot_code_value = (slot_code or "").strip().lower()

    parse_warning: Optional[str] = None
    try:
        quantity_value = _parse_int(quantity) or 1
    except ValueError:
        quantity_value = 1
        parse_warning = "数量格式错误，已自动重置为 1"

    try:
        ttl_value = _parse_int(ttl_days)
        custom_ttl_value = _parse_int(custom_ttl_days)
    except ValueError:
        msg = "有效期参数需为数字"
        target = _append_message(_sanitize_return_path(return_to), msg)
        return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)

    try:
        licenses, batch = service.create_licenses(
            type_code=type_value,
            card_code=card_code_value,
            quantity=quantity_value,
            custom_prefix=prefix_value,
            ttl_days=ttl_value,
            custom_ttl_days=custom_ttl_value,
            slot_code=slot_code_value,
        )
    except ValueError as exc:
        db.rollback()
        error = str(exc)
        error_map = {
            "card_type_not_found": "选择的卡密类型不存在",
            "card_type_disabled": "选择的卡密类型已停用",
            "card_code_exists": "卡密已存在",
            "card_code_blank": "卡密不能为空",
            "card_code_too_long": "卡密长度超出限制",
            "card_code_requires_single_quantity": "自定义卡密时数量必须为 1",
            "quantity_invalid": "生成数量无效",
            "quantity_too_large": "一次最多生成 500 个卡密",
            "custom_ttl_invalid": "自定义有效期无效",
            "ttl_invalid": "有效期无效",
            "prefix_invalid": "自定义前缀包含非法字符",
            "prefix_too_long": "自定义前缀长度超出限制",
            "slot_code_required": "请选择软件位",
            "slot_not_found": "未找到该软件位",
        }
        msg = error_map.get(error, error)
    except IntegrityError:
        db.rollback()
        msg = "卡密已存在"
    else:
        if not licenses:
            msg = "未生成卡密"
        elif len(licenses) == 1:
            license_obj = licenses[0]
            expire_text = license_obj.expire_at.isoformat() if license_obj.expire_at else "永久有效"
            batch_label = batch.batch_code if batch else "--"
            msg = f"已创建卡密 {license_obj.card_code}（到期：{expire_text}，批次：{batch_label}）"
        else:
            batch_label = batch.batch_code if batch else "--"
            msg = f"已批量创建 {len(licenses)} 个卡密，批次号 {batch_label}"

    if parse_warning:
        msg = f"{parse_warning}；{msg}" if msg else parse_warning

    target = _sanitize_return_path(return_to)
    target = _append_message(target, msg)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@licenses_router.post("/revoke")
def revoke_license(
    request: Request,
    card_code: str = Form(...),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("licenses", "manage")),
):
    service = _license_service(db, principal)
    success = service.revoke(card_code)
    if success:
        msg = f"卡密 {card_code} 已撤销"
    else:
        msg = f"未找到卡密 {card_code}"

    target = _sanitize_return_path(return_to)
    if target == "/admin/licenses":
        # 默认回列表，保持分页筛选参数
        query = _build_list_query("all", 1, DEFAULT_PAGE_SIZE, None, msg)
        target = f"/admin/licenses?{query}"
    else:
        target = _append_message(target, msg)

    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@licenses_router.get("/{card_code}")
def license_detail(
    request: Request,
    card_code: str,
    message: Optional[str] = None,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("licenses", "view")),
):
    license_obj = _get_license_or_404(db, card_code)
    context = _build_license_detail_context(request, license_obj, db, message=message)
    return templates.TemplateResponse(request, "admin/licenses/detail.html", context)


@licenses_router.post("/{card_code}/extend")
def extend_license_action(
    request: Request,
    card_code: str,
    extra_days: int = Form(...),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("licenses", "manage")),
):
    target = _sanitize_return_path(return_to)
    service = _license_service(db, principal)
    extra_days = max(extra_days, 0)
    try:
        if extra_days <= 0:
            raise ValueError("延期天数必须大于 0")
        license_obj = service.extend_expiry(card_code, extra_days)
        if not license_obj:
            msg = f"未找到卡密 {card_code}"
        else:
            expire_text = license_obj.expire_at.isoformat() if license_obj.expire_at else "未设置"
            msg = f"已将 {card_code} 延期 {extra_days} 天（到期：{expire_text}）"
    except ValueError as exc:
        db.rollback()
        msg = str(exc)

    target = _append_message(target, msg)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@licenses_router.post("/{card_code}/offline")
def generate_offline_license_action(
    request: Request,
    card_code: str,
    fingerprint: str = Form(...),
    ttl_days: int = Form(7),
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("licenses", "manage")),
):
    license_obj = _get_license_or_404(db, card_code)
    service = _license_service(db, principal)

    message: Optional[str] = None
    offline_result: Optional[dict[str, str]] = None

    fingerprint = fingerprint.strip()
    if not fingerprint:
        message = "设备指纹不能为空"
    else:
        ttl_days = max(ttl_days, 0)
        if ttl_days <= 0:
            message = "离线授权有效期必须大于 0 天"
        else:
            expires_at = datetime.now(timezone.utc) + timedelta(days=ttl_days)
            try:
                blob, signature, effective_expiry, status = service.generate_offline_license(
                    card_code, fingerprint, expires_at
                )
            except ValueError as exc:
                message = str(exc)
            else:
                if status == "ok" and blob and signature and effective_expiry:
                    offline_result = {
                        "fingerprint": fingerprint,
                        "expires_at": effective_expiry.isoformat(),
                        "license_blob": blob,
                        "signature": signature,
                    }
                    message = f"离线授权已生成，将于 {offline_result['expires_at']} 过期。"
                elif status == "license_expired":
                    message = "卡密已过期，无法生成离线授权。"
                elif status == "license_not_found":
                    message = "未找到卡密"
                else:
                    message = f"离线授权生成失败：{status}"

    db.refresh(license_obj)
    context = _build_license_detail_context(
        request,
        license_obj,
        db,
        message=message,
        offline_result=offline_result,
    )
    return templates.TemplateResponse(request, "admin/licenses/detail.html", context)


@licenses_router.post("/{card_code}/reset")
def reset_license_action(
    request: Request,
    card_code: str,
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("licenses", "manage")),
):
    service = _license_service(db, principal)
    success = service.reset_license(card_code)
    if success:
        msg = f"已重置 {card_code}，激活记录已清空"
    else:
        msg = f"未找到卡密 {card_code}"

    target = _append_message(_sanitize_return_path(return_to), msg)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)

@cdn_router.get("/")
def cdn_page(
    request: Request,
    message: Optional[str] = None,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("cdn", "view")),
):
    service = CDNService(db)
    endpoints = service.list_endpoints()
    tasks = service.list_recent_tasks(limit=20)

    endpoint_rows: list[dict[str, object]] = []
    provider_stats: dict[str, int] = {}
    active_count = 0
    paused_count = 0
    error_count = 0

    for endpoint in endpoints:
        provider_stats[endpoint.provider] = provider_stats.get(endpoint.provider, 0) + 1
        if endpoint.status == CDNEndpointStatus.ACTIVE.value:
            active_count += 1
        elif endpoint.status == CDNEndpointStatus.PAUSED.value:
            paused_count += 1
        elif endpoint.status == CDNEndpointStatus.ERROR.value:
            error_count += 1

        last_task = None
        if endpoint.tasks:
            last_task = max(
                endpoint.tasks,
                key=lambda t: t.created_at or datetime.min.replace(tzinfo=timezone.utc),
            )

        endpoint_rows.append(
            {
                "endpoint": endpoint,
                "last_task": last_task,
                "task_count": len(endpoint.tasks or []),
            }
        )

    task_rows = []
    for task in tasks:
        task_rows.append(
            {
                "task": task,
                "endpoint": getattr(task, "endpoint", None),
            }
        )

    context = _base_context(
        request,
        message=message,
        page_title="CDN 管理",
        page_subtitle="维护加速域名与刷新任务，确保资源及时更新。",
        page_description="统一管理 CDN 加速节点，快速发起刷新与预取任务。",
        active_page="cdn",
        endpoints=endpoint_rows,
        endpoint_count=len(endpoints),
        provider_stats=provider_stats,
        endpoint_statuses={
            "active": active_count,
            "paused": paused_count,
            "error": error_count,
        },
        tasks=task_rows,
        status_labels=CDN_STATUS_LABELS,
        task_status_labels=CDN_TASK_STATUS_LABELS,
        task_types=[
            (CDNTaskType.PURGE.value, "刷新缓存"),
            (CDNTaskType.PREFETCH.value, "预取内容"),
        ],
    )
    return templates.TemplateResponse(request, "admin/cdn/index.html", context)

@cdn_router.post("/endpoints")
def create_cdn_endpoint_action(
    request: Request,
    name: str = Form(...),
    domain: str = Form(...),
    provider: str = Form(...),
    origin: str = Form(...),
    notes: Optional[str] = Form(None),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("cdn", "manage")),
):
    service = CDNService(db)
    try:
        service.create_endpoint(name=name, domain=domain, provider=provider, origin=origin, notes=notes)
    except ValueError as exc:
        db.rollback()
        error_map = {
            "name_too_short": "名称至少需要 3 个字符",
            "domain_invalid": "域名格式不正确",
            "provider_required": "请选择或填写加速服务提供商",
            "origin_required": "请填写源站地址",
            "domain_exists": "域名已存在，请勿重复添加",
        }
        message = error_map.get(str(exc), f"创建失败: {exc}")
    else:
        message = "已创建新的 CDN 节点"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/cdn"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@cdn_router.post("/endpoints/{endpoint_id}/status")
def update_cdn_endpoint_status_action(
    request: Request,
    endpoint_id: int,
    status: str = Form(...),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("cdn", "manage")),
):
    service = CDNService(db)
    message: str
    try:
        enum_status = CDNEndpointStatus(status)
    except ValueError:
        message = "状态值无效"
    else:
        try:
            service.set_endpoint_status(endpoint_id, enum_status)
        except ValueError as exc:
            db.rollback()
            if str(exc) == "endpoint_not_found":
                message = "未找到指定的 CDN 节点"
            else:
                message = f"更新失败: {exc}"
        else:
            message = "节点状态已更新"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/cdn"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@cdn_router.post("/endpoints/{endpoint_id}/tasks")
def create_cdn_task_action(
    request: Request,
    endpoint_id: int,
    task_type: str = Form(...),
    payload: Optional[str] = Form(None),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("cdn", "manage")),
):
    service = CDNService(db)
    try:
        enum_type = CDNTaskType(task_type)
    except ValueError:
        enum_type = None

    if not enum_type:
        message = "任务类型无效"
    else:
        try:
            service.create_task(endpoint_id=endpoint_id, task_type=enum_type, payload=payload)
        except ValueError as exc:
            db.rollback()
            error = str(exc)
            if error == "endpoint_not_found":
                message = "未找到指定的 CDN 节点"
            else:
                message = f"创建任务失败: {exc}"
        else:
            message = "任务已提交"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/cdn"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@software_router.get("/")
def software_page(
    request: Request,
    message: Optional[str] = None,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("software", "view")),
):
    service = SoftwareService(db)
    slots = service.list_slots()

    slot_rows = []
    active_slots = 0
    paused_slots = 0
    total_packages = 0

    for slot in slots:
        if slot.status == SoftwareSlotStatus.ACTIVE.value:
            active_slots += 1
        elif slot.status == SoftwareSlotStatus.PAUSED.value:
            paused_slots += 1

        packages = service.list_packages(slot.id, limit=6)
        total_packages += len(packages)

        slot_rows.append(
            {
                "slot": slot,
                "packages": packages,
            }
        )

    context = _base_context(
        request,
        message=message,
        page_title="软件位管理",
        page_subtitle="配置灰度与线上版本，快速创建新包与发布。",
        page_description="统一管理软件位与安装包版本，支持一键发布与回滚。",
        active_page="software",
        slots=slot_rows,
        slot_count=len(slots),
        active_slots=active_slots,
        paused_slots=paused_slots,
        total_packages=total_packages,
        slot_status_labels=SOFTWARE_SLOT_STATUS_LABELS,
        package_status_labels=SOFTWARE_PACKAGE_STATUS_LABELS,
    )
    return templates.TemplateResponse(request, "admin/software/index.html", context)


@software_router.post("/slots")
def create_software_slot_action(
    request: Request,
    code: str = Form(...),
    name: str = Form(...),
    product_line: Optional[str] = Form(None),
    channel: Optional[str] = Form(None),
    gray_ratio: Optional[int] = Form(None),
    notes: Optional[str] = Form(None),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("software", "manage")),
):
    service = SoftwareService(db)
    try:
        service.create_slot(
            code=code,
            name=name,
            product_line=product_line,
            channel=channel,
            gray_ratio=gray_ratio,
            notes=notes,
        )
    except ValueError as exc:
        db.rollback()
        error_map = {
            "code_too_short": "标识至少需要 2 个字符",
            "name_too_short": "名称至少需要 3 个字符",
            "gray_ratio_invalid": "灰度比例应在 0-100 之间",
            "slot_code_exists": "该标识已存在，请使用其他标识",
        }
        message = error_map.get(str(exc), f"创建失败: {exc}")
    else:
        message = "已创建软件位"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/software"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@software_router.post("/slots/{slot_id}/status")
def update_software_slot_status_action(
    request: Request,
    slot_id: int,
    status: str = Form(...),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("software", "manage")),
):
    try:
        enum_status = SoftwareSlotStatus(status)
    except ValueError:
        enum_status = None

    service = SoftwareService(db)
    if not enum_status:
        message = "状态值无效"
    else:
        try:
            service.set_slot_status(slot_id, enum_status)
        except ValueError as exc:
            db.rollback()
            if str(exc) == "slot_not_found":
                message = "未找到指定的软件位"
            else:
                message = f"更新失败: {exc}"
        else:
            message = "状态已更新"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/software"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@software_router.post("/slots/{slot_id}/packages")
def create_software_package_action(
    request: Request,
    slot_id: int,
    version: str = Form(...),
    file_url: Optional[str] = Form(None),
    checksum: Optional[str] = Form(None),
    release_notes: Optional[str] = Form(None),
    promote: Optional[bool] = Form(False),
    mark_critical: Optional[bool] = Form(False),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("software", "manage")),
):
    promote_flag = bool(promote)
    critical_flag = bool(mark_critical)
    service = SoftwareService(db)
    try:
        service.create_package(
            slot_id=slot_id,
            version=version,
            file_url=file_url,
            checksum=checksum,
            release_notes=release_notes,
            promote=promote_flag,
            mark_critical=critical_flag,
        )
    except ValueError as exc:
        db.rollback()
        error = str(exc)
        if error == "slot_not_found":
            message = "未找到指定的软件位"
        elif error == "version_required":
            message = "请输入版本号"
        elif error == "version_exists":
            message = "该版本已存在"
        else:
            message = f"创建安装包失败: {exc}"
    else:
        message = "安装包创建成功"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/software"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@software_router.post("/packages/{package_id}/promote")
def promote_software_package_action(
    request: Request,
    package_id: int,
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("software", "manage")),
):
    service = SoftwareService(db)
    try:
        service.promote_package(package_id)
    except ValueError as exc:
        db.rollback()
        if str(exc) == "package_not_found":
            message = "未找到安装包"
        else:
            message = f"发布失败: {exc}"
    else:
        message = "已发布为当前版本"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/software"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@software_router.post("/packages/{package_id}/retire")
def retire_software_package_action(
    request: Request,
    package_id: int,
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("software", "manage")),
):
    service = SoftwareService(db)
    try:
        service.retire_package(package_id)
    except ValueError as exc:
        db.rollback()
        if str(exc) == "package_not_found":
            message = "未找到安装包"
        else:
            message = f"下线失败: {exc}"
    else:
        message = "安装包已下线"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/software"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@settings_router.get("/")
def settings_page(
    request: Request,
    message: Optional[str] = None,
    module: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    actor_type: Optional[str] = Query(None),
    actor_role: Optional[str] = Query(None),
    actor_id: Optional[int] = Query(None),
    target_type: Optional[str] = Query(None),
    target_id: Optional[str] = Query(None),
    license_id: Optional[int] = Query(None),
    request_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None, alias="q"),
    start_param: Optional[str] = Query(None, alias="start"),
    end_param: Optional[str] = Query(None, alias="end"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("settings", "view")),
):
    admin_service = AdminUserService(db)
    admins = admin_service.list_admins()
    role_service = RoleService(db)
    roles = role_service.list_roles(include_inactive=False)

    module_filter = _sanitize_optional_str(module)
    action_filter = _sanitize_optional_str(action)
    actor_type_filter = _sanitize_optional_str(actor_type)
    actor_role_filter = _sanitize_optional_str(actor_role)
    target_type_filter = _sanitize_optional_str(target_type)
    target_id_filter = _sanitize_optional_str(target_id)
    request_id_filter = _sanitize_optional_str(request_id)
    start_str = _sanitize_optional_str(start_param)
    end_str = _sanitize_optional_str(end_param)
    search_filter = _sanitize_optional_str(search)

    start_dt = _parse_filter_datetime(start_str)
    end_dt = _parse_filter_datetime(end_str)
    if start_dt and end_dt and end_dt < start_dt:
        start_dt, end_dt = end_dt, start_dt

    start_value = _format_datetime_input(start_dt, start_str)
    end_value = _format_datetime_input(end_dt, end_str)

    page = max(page, 1)
    page_size = max(1, min(page_size, 100))
    offset = (page - 1) * page_size

    audit_service = _audit_service(db)
    logs, total = audit_service.list_logs(
        module=module_filter,
        action=action_filter,
        actor_type=actor_type_filter,
        actor_id=actor_id,
        actor_role=actor_role_filter,
        target_type=target_type_filter,
        target_id=target_id_filter,
        license_id=license_id,
        request_id=request_id_filter,
        search=search_filter,
        start=start_dt,
        end=end_dt,
        limit=page_size,
        offset=offset,
    )

    total_pages = max((total + page_size - 1) // page_size, 1) if total else 1
    if total and page > total_pages:
        page = total_pages
        offset = (page - 1) * page_size
        logs, total = audit_service.list_logs(
            module=module_filter,
            action=action_filter,
            actor_type=actor_type_filter,
            actor_id=actor_id,
            actor_role=actor_role_filter,
            target_type=target_type_filter,
            target_id=target_id_filter,
            license_id=license_id,
            request_id=request_id_filter,
            search=search_filter,
            start=start_dt,
            end=end_dt,
            limit=page_size,
            offset=offset,
        )
        total_pages = max((total + page_size - 1) // page_size, 1)
    elif not total:
        page = 1
        offset = 0
        total_pages = 1

    module_options = [
        value
        for value in
        db.scalars(
            select(models.AuditLog.module)
            .where(models.AuditLog.module.isnot(None))
            .distinct()
            .order_by(models.AuditLog.module.asc())
        ).all()
        if value
    ]

    actor_type_options = [
        value
        for value in
        db.scalars(
            select(models.AuditLog.actor_type)
            .where(models.AuditLog.actor_type.isnot(None))
            .distinct()
            .order_by(models.AuditLog.actor_type.asc())
        ).all()
        if value
    ]

    target_type_options = [
        value
        for value in
        db.scalars(
            select(models.AuditLog.target_type)
            .where(models.AuditLog.target_type.isnot(None))
            .distinct()
            .order_by(models.AuditLog.target_type.asc())
        ).all()
        if value
    ]

    audit_filters = {
        "module": module_filter,
        "action": action_filter,
        "actor_type": actor_type_filter,
        "actor_role": actor_role_filter,
        "actor_id": actor_id,
        "target_type": target_type_filter,
        "target_id": target_id_filter,
        "license_id": license_id,
        "request_id": request_id_filter,
        "search": search_filter,
        "start": start_value,
        "end": end_value,
    }

    audit_pagination = {
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "prev_page": page - 1 if page > 1 else 1,
        "next_page": page + 1 if page < total_pages else total_pages,
        "offset": offset,
    }

    context = _base_context(
        request,
        message=message,
        page_title="系统设置",
        page_subtitle="维护后台管理员账号与关键配置。",
        page_description="管理管理员账号、重置密码与启用状态，查看系统基础配置。",
        active_page="settings",
        admins=admins,
        roles=roles,
        super_admin={
            "username": settings.admin_username,
            "role": "superadmin",
        },
        audit_logs=logs,
        audit_filters=audit_filters,
        audit_pagination=audit_pagination,
        audit_module_options=module_options,
        audit_actor_type_options=actor_type_options,
        audit_target_type_options=target_type_options,
        audit_start_value=start_value,
        audit_end_value=end_value,
    )
    return templates.TemplateResponse(request, "admin/settings/index.html", context)


@settings_router.get("/audit/export")
def export_audit_logs(
    request: Request,
    module: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    actor_type: Optional[str] = Query(None),
    actor_role: Optional[str] = Query(None),
    actor_id: Optional[int] = Query(None),
    target_type: Optional[str] = Query(None),
    target_id: Optional[str] = Query(None),
    license_id: Optional[int] = Query(None),
    request_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None, alias="q"),
    start_param: Optional[str] = Query(None, alias="start"),
    end_param: Optional[str] = Query(None, alias="end"),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("settings", "view")),
):
    module_filter = _sanitize_optional_str(module)
    action_filter = _sanitize_optional_str(action)
    actor_type_filter = _sanitize_optional_str(actor_type)
    actor_role_filter = _sanitize_optional_str(actor_role)
    target_type_filter = _sanitize_optional_str(target_type)
    target_id_filter = _sanitize_optional_str(target_id)
    request_id_filter = _sanitize_optional_str(request_id)
    search_filter = _sanitize_optional_str(search)
    start_str = _sanitize_optional_str(start_param)
    end_str = _sanitize_optional_str(end_param)

    start_dt = _parse_filter_datetime(start_str)
    end_dt = _parse_filter_datetime(end_str)
    if start_dt and end_dt and end_dt < start_dt:
        start_dt, end_dt = end_dt, start_dt

    audit_service = _audit_service(db)
    query_kwargs = {
        "module": module_filter,
        "action": action_filter,
        "actor_type": actor_type_filter,
        "actor_id": actor_id,
        "actor_role": actor_role_filter,
        "target_type": target_type_filter,
        "target_id": target_id_filter,
        "license_id": license_id,
        "request_id": request_id_filter,
        "search": search_filter,
        "start": start_dt,
        "end": end_dt,
    }

    logs: list[models.AuditLog] = []
    chunk_size = 1000
    offset = 0

    while True:
        batch, total = audit_service.list_logs(limit=chunk_size, offset=offset, **query_kwargs)
        if not batch:
            break
        logs.extend(batch)
        if len(logs) >= total:
            break
        offset += chunk_size
        if offset > 10000:
            # Prevent excessive export size
            break

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "created_at",
            "module",
            "action",
            "event_type",
            "actor_type",
            "actor_id",
            "actor_name",
            "actor_role",
            "target_type",
            "target_id",
            "target_name",
            "license_id",
            "message",
            "request_id",
            "ip_address",
            "payload",
        ]
    )

    for log in logs:
        payload_str = json.dumps(log.payload, ensure_ascii=False, sort_keys=True) if log.payload else ""
        writer.writerow(
            [
                log.created_at.isoformat() if log.created_at else "",
                log.module or "",
                log.action or "",
                log.event_type or "",
                log.actor_type or "",
                log.actor_id if log.actor_id is not None else "",
                log.actor_name or "",
                log.actor_role or "",
                log.target_type or "",
                log.target_id or "",
                log.target_name or "",
                log.license_id if log.license_id is not None else "",
                log.message or "",
                log.request_id or "",
                log.ip_address or "",
                payload_str,
            ]
        )

    output.seek(0)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    filename = f"audit_logs_{timestamp}.csv"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store",
    }
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers=headers)


@settings_router.post("/admins")
def create_admin_user_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    role: str = Form("admin"),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("settings", "manage")),
):
    username = (username or "").strip()
    role = (role or "admin").strip() or "admin"
    if password != confirm_password:
        message = "两次密码不一致"
    else:
        service = _admin_user_service(db, principal)
        try:
            service.create_admin(username=username, password=password, role_code=role)
        except ValueError as exc:
            db.rollback()
            error = str(exc)
            if error == "username_too_short":
                message = "用户名至少 3 个字符"
            elif error == "password_too_short":
                message = "密码至少 8 位"
            elif error == "username_taken":
                message = "用户名已存在"
            else:
                message = f"创建失败: {exc}"
        else:
            message = f"已创建管理员 {username}"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/settings"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@settings_router.post("/admins/{admin_id}/password")
def reset_admin_password_action(
    request: Request,
    admin_id: int,
    password: str = Form(...),
    confirm_password: str = Form(...),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("settings", "manage")),
):
    if password != confirm_password:
        message = "两次密码不一致"
    else:
        service = _admin_user_service(db, principal)
        try:
            service.reset_password(admin_id, password)
        except ValueError as exc:
            db.rollback()
            if str(exc) == "password_too_short":
                message = "密码至少 8 位"
            elif str(exc) == "admin_not_found":
                message = "未找到管理员"
            else:
                message = f"重置失败: {exc}"
        else:
            message = "密码已重置"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/settings"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@settings_router.post("/admins/{admin_id}/status")
def toggle_admin_status_action(
    request: Request,
    admin_id: int,
    is_active: bool = Form(...),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("settings", "manage")),
):
    service = _admin_user_service(db, principal)
    try:
        service.set_active(admin_id, is_active)
    except ValueError as exc:
        db.rollback()
        if str(exc) == "admin_not_found":
            message = "未找到管理员"
        else:
            message = f"更新失败: {exc}"
    else:
        message = "状态已更新"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/settings"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


router.include_router(dashboard_router)
router.include_router(licenses_router)
router.include_router(license_types_router)
router.include_router(users_router)
router.include_router(software_router)
router.include_router(cdn_router)
router.include_router(settings_router)
api_router.include_router(api_users_router, tags=["admin-api-users"])
api_router.include_router(api_license_types_router, tags=["admin-api-license-types"])
api_router.include_router(api_licenses_router, tags=["admin-api-licenses"])
router.include_router(api_router, tags=["admin-api"])

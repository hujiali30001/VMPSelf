from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload
from starlette.status import HTTP_303_SEE_OTHER, HTTP_401_UNAUTHORIZED

from app.api.deps import get_db
from app.core.settings import get_settings
from app.db import License, LicenseStatus, models
from app.schemas import (
    LicenseAdminResponse,
    LicenseBatchCreateResponse,
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
from app.services.card_type_service import LicenseCardTypeService
from app.services.license_service import LicenseService
from app.services.user_service import UserService

router = APIRouter()
settings = get_settings()
security = HTTPBasic()

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))

STATUS_LABELS = {
    LicenseStatus.UNUSED.value: "未使用",
    LicenseStatus.ACTIVE.value: "已激活",
    LicenseStatus.REVOKED.value: "已撤销",
    LicenseStatus.EXPIRED.value: "已过期",
}


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

    return {
        "request": request,
        "license": license_obj,
        "registered_user": license_obj.user,
        "latest_seen": latest_seen,
        "activations": activations,
        "audit_logs": audit_logs,
        "message": message,
        "status_labels": STATUS_LABELS,
        "expires_in_days": expires_in_days,
        "offline_result": offline_result,
    }


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

    return {
        "request": request,
        "user_obj": user,
        "license": license_obj,
        "activations": activations,
        "audit_logs": audit_logs,
        "latest_seen": latest_seen,
        "expires_in_days": expires_in_days,
        "message": message,
        "status_labels": STATUS_LABELS,
    }


def require_admin(credentials: HTTPBasicCredentials = Depends(security)) -> HTTPBasicCredentials:
    username_match = secrets.compare_digest(credentials.username, settings.admin_username)
    password_match = secrets.compare_digest(credentials.password, settings.admin_password)
    if not (username_match and password_match):
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials


@router.get("/api/users", response_model=UserListResponse)
def api_list_users(
    offset: int = 0,
    limit: int = 50,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
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


@router.get("/api/users/{user_id}", response_model=UserDetailResponse)
def api_get_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    user = UserService(db).get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user_not_found")
    serialized = _serialize_user(user)
    assert serialized is not None
    return serialized


@router.patch("/api/users/{user_id}", response_model=UserDetailResponse)
def api_update_user(
    user_id: int,
    payload: UserUpdateRequest,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    if payload.username is None and payload.password is None and payload.card_code is None:
        raise HTTPException(status_code=400, detail="no_fields_provided")

    service = UserService(db)
    try:
        user = service.update_user(
            user_id,
            username=payload.username,
            password=payload.password,
            card_code=payload.card_code,
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
        }:
            status_code = 404 if message == "user_not_found" else 400
            raise HTTPException(status_code=status_code, detail=message)
        raise

    serialized = _serialize_user(user)
    assert serialized is not None
    return serialized


@router.delete("/api/users/{user_id}", status_code=204)
def api_delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    if not UserService(db).delete_user(user_id):
        raise HTTPException(status_code=404, detail="user_not_found")
    return Response(status_code=204)


@router.get("/api/license-types", response_model=LicenseCardTypeListResponse)
def api_list_license_types(
    include_inactive: bool = True,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    service = LicenseCardTypeService(db)
    items = service.list_types(include_inactive=include_inactive)
    return {
        "items": [_serialize_card_type(item) for item in items if item],
        "total": len(items),
    }


@router.post("/api/license-types", response_model=LicenseCardTypeResponse, status_code=201)
def api_create_license_type(
    payload: LicenseCardTypeCreateRequest,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
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


@router.patch("/api/license-types/{type_id}", response_model=LicenseCardTypeResponse)
def api_update_license_type(
    type_id: int,
    payload: LicenseCardTypeUpdateRequest,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
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


@router.delete("/api/license-types/{type_id}", status_code=204)
def api_delete_license_type(
    type_id: int,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
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


@router.get("/api/licenses", response_model=LicenseListResponse)
def api_list_licenses(
    status: str = "all",
    offset: int = 0,
    limit: int = 50,
    search: Optional[str] = None,
    type_code: Optional[str] = None,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
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


@router.post("/api/licenses", response_model=LicenseBatchCreateResponse, status_code=201)
def api_create_license(
    payload: LicenseCreateRequest,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    service = LicenseService(db)
    try:
        licenses, batch_id = service.create_licenses(
            type_code=payload.type_code,
            card_code=payload.card_code,
            quantity=payload.quantity,
            custom_prefix=payload.custom_prefix,
            ttl_days=payload.ttl_days,
            custom_ttl_days=payload.custom_ttl_days,
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
        }:
            raise HTTPException(status_code=400, detail=message)
        raise
    except IntegrityError:
        raise HTTPException(status_code=400, detail="card_code_exists")

    return {
        "items": [_serialize_license(obj) for obj in licenses],
        "batch_id": batch_id,
        "quantity": len(licenses),
    }


@router.get("/api/licenses/{card_code}", response_model=LicenseAdminResponse)
def api_get_license(
    card_code: str,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    license_obj = LicenseService(db).get_license(card_code)
    if not license_obj:
        raise HTTPException(status_code=404, detail="license_not_found")
    return _serialize_license(license_obj)


@router.patch("/api/licenses/{card_code}", response_model=LicenseAdminResponse)
def api_update_license(
    card_code: str,
    payload: LicenseUpdateRequest,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    if payload.expire_at is None and payload.status is None and payload.bound_fingerprint is None:
        raise HTTPException(status_code=400, detail="no_fields_provided")

    service = LicenseService(db)
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


@router.delete("/api/licenses/{card_code}", status_code=204)
def api_delete_license(
    card_code: str,
    force: bool = False,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    service = LicenseService(db)
    try:
        success = service.delete_license(card_code, force=force)
    except ValueError as exc:
        if str(exc) == "license_active":
            raise HTTPException(status_code=400, detail="license_active")
        raise

    if not success:
        raise HTTPException(status_code=404, detail="license_not_found")
    return Response(status_code=204)


@router.get("/license-types")
def license_types_page(
    request: Request,
    edit: Optional[int] = None,
    message: Optional[str] = None,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
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

    return templates.TemplateResponse(
        request,
        "admin/card_types/index.html",
        {
            "request": request,
            "card_types": card_type_rows,
            "total": len(card_types),
            "total_active": total_active,
            "total_inactive": total_inactive,
            "edit_type": edit_type,
            "message": message,
            "return_to": return_to,
        },
    )


@router.post("/license-types/create")
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
    _: HTTPBasicCredentials = Depends(require_admin),
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


@router.post("/license-types/{type_id}/update")
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
    _: HTTPBasicCredentials = Depends(require_admin),
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


@router.post("/license-types/{type_id}/toggle")
def toggle_license_type_action(
    request: Request,
    type_id: int,
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
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


@router.post("/license-types/{type_id}/delete")
def delete_license_type_action(
    request: Request,
    type_id: int,
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
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


@router.get("/users")
def users_page(
    request: Request,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    q: Optional[str] = None,
    message: Optional[str] = None,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
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

    return templates.TemplateResponse(
        request,
        "admin/users.html",
        {
            "request": request,
            "users": user_rows,
            "page": page,
            "page_size": page_size,
            "query": search_query or "",
            "total": total,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "prev_page": page - 1,
            "next_page": page + 1,
            "message": message,
            "status_labels": STATUS_LABELS,
            "status_counts": status_counts,
        },
    )


@router.get("/users/{user_id}")
def user_detail(
    request: Request,
    user_id: int,
    message: Optional[str] = None,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    user = _get_user_or_404(db, user_id)
    context = _build_user_detail_context(request, user, db, message=message)
    return templates.TemplateResponse(request, "admin/user_detail.html", context)


@router.post("/users/register")
def register_user_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    card_code: str = Form(...),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    username = username.strip()
    card_code = card_code.strip()
    message: str

    if password != confirm_password:
        message = "两次输入的密码不一致"
    else:
        service = UserService(db)
        try:
            user = service.register(username, password, card_code)
        except ValueError as exc:
            db.rollback()
            message = str(exc)
        else:
            message = f"已创建用户 {user.username}"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/users"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@router.post("/users/{user_id}/profile")
def update_user_profile_action(
    request: Request,
    user_id: int,
    username: Optional[str] = Form(None),
    card_code: Optional[str] = Form(None),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    username = (username or "").strip()
    card_code = (card_code or "").strip()

    updates: dict[str, Optional[str]] = {}
    if username:
        updates["username"] = username
    if card_code:
        updates["card_code"] = card_code

    if not updates:
        message = "请填写需要更新的字段"
    else:
        service = UserService(db)
        try:
            service.update_user(user_id, **updates)
        except ValueError as exc:
            db.rollback()
            message = str(exc)
        else:
            message = "用户信息已更新"

    target = _append_message(
        _sanitize_return_path(return_to, fallback=f"/admin/users/{user_id}"),
        message,
    )
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@router.post("/users/{user_id}/password")
def update_user_password_action(
    request: Request,
    user_id: int,
    password: str = Form(...),
    confirm_password: str = Form(...),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    if password != confirm_password:
        message = "两次输入的密码不一致"
    else:
        service = UserService(db)
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


@router.post("/users/{user_id}/delete")
def delete_user_action(
    request: Request,
    user_id: int,
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    service = UserService(db)
    success = service.delete_user(user_id)
    message = "用户已删除" if success else "未找到指定用户"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/users"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)

@router.get("/licenses")
def licenses_page(
    request: Request,
    status: str = "all",
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    q: Optional[str] = None,
    type_code: Optional[str] = None,
    message: str | None = None,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
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

    return templates.TemplateResponse(
        request,
        "admin/licenses/index.html",
        {
            "request": request,
            "licenses": license_rows,
            "status": status,
            "page": page,
            "page_size": page_size,
            "query": search_query or "",
            "total": total,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "prev_page": page - 1,
            "next_page": page + 1,
            "statuses": statuses,
            "status_counts": status_counts,
            "message": message,
            "status_labels": STATUS_LABELS,
            "card_types": card_types,
            "active_card_types": active_card_types,
            "selected_type_code": type_query or "",
            "selected_card_type": selected_card_type,
            "type_breakdown": type_breakdown,
            "selected_type_total": selected_type_total,
            "type_counts": type_counts,
            "type_filter_urls": type_filter_urls,
        },
    )


@router.post("/licenses/create")
def create_license_action(
    request: Request,
    card_code: Optional[str] = Form(None),
    type_code: Optional[str] = Form(None),
    quantity: Optional[str] = Form("1"),
    custom_prefix: Optional[str] = Form(None),
    ttl_days: Optional[str] = Form(None),
    custom_ttl_days: Optional[str] = Form(None),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    service = LicenseService(db)

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
        licenses, batch_id = service.create_licenses(
            type_code=type_value,
            card_code=card_code_value,
            quantity=quantity_value,
            custom_prefix=prefix_value,
            ttl_days=ttl_value,
            custom_ttl_days=custom_ttl_value,
        )
    except ValueError as exc:
        db.rollback()
        msg = str(exc)
    except IntegrityError:
        db.rollback()
        msg = "卡密已存在"
    else:
        if not licenses:
            msg = "未生成卡密"
        elif len(licenses) == 1:
            license_obj = licenses[0]
            expire_text = license_obj.expire_at.isoformat() if license_obj.expire_at else "永久有效"
            msg = f"已创建卡密 {license_obj.card_code}（到期：{expire_text}）"
        else:
            msg = f"已批量创建 {len(licenses)} 个卡密，批次号 {batch_id}"

    if parse_warning:
        msg = f"{parse_warning}；{msg}" if msg else parse_warning

    target = _sanitize_return_path(return_to)
    target = _append_message(target, msg)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@router.post("/licenses/revoke")
def revoke_license(
    request: Request,
    card_code: str = Form(...),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    service = LicenseService(db)
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


@router.get("/licenses/{card_code}")
def license_detail(
    request: Request,
    card_code: str,
    message: Optional[str] = None,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    license_obj = _get_license_or_404(db, card_code)
    context = _build_license_detail_context(request, license_obj, db, message=message)
    return templates.TemplateResponse(request, "admin/license_detail.html", context)


@router.post("/licenses/{card_code}/extend")
def extend_license_action(
    request: Request,
    card_code: str,
    extra_days: int = Form(...),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    target = _sanitize_return_path(return_to)
    service = LicenseService(db)
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


@router.post("/licenses/{card_code}/offline")
def generate_offline_license_action(
    request: Request,
    card_code: str,
    fingerprint: str = Form(...),
    ttl_days: int = Form(7),
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    license_obj = _get_license_or_404(db, card_code)
    service = LicenseService(db)

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
    return templates.TemplateResponse(request, "admin/license_detail.html", context)


@router.post("/licenses/{card_code}/reset")
def reset_license_action(
    request: Request,
    card_code: str,
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    service = LicenseService(db)
    success = service.reset_license(card_code)
    if success:
        msg = f"已重置 {card_code}，激活记录已清空"
    else:
        msg = f"未找到卡密 {card_code}"

    target = _append_message(_sanitize_return_path(return_to), msg)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)

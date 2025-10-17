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
from sqlalchemy.orm import Session
from starlette.status import HTTP_303_SEE_OTHER, HTTP_401_UNAUTHORIZED

from app.api.deps import get_db
from app.core.settings import get_settings
from app.db import License, LicenseStatus, models
from app.schemas import (
    LicenseAdminResponse,
    LicenseCreateRequest,
    LicenseListResponse,
    LicenseUpdateRequest,
    UserDetailResponse,
    UserListResponse,
    UserUpdateRequest,
)
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
) -> str:
    params: dict[str, str] = {
        "status": status,
        "page": str(page),
        "page_size": str(page_size),
    }
    if q:
        params["q"] = q
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


@router.get("/api/licenses", response_model=LicenseListResponse)
def api_list_licenses(
    status: str = "all",
    offset: int = 0,
    limit: int = 50,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    offset = max(offset, 0)
    limit = max(1, min(limit, 200))
    search_query = search.strip() if search else None

    service = LicenseService(db)
    items = service.list_licenses(status=status, search=search_query, offset=offset, limit=limit)

    total_stmt = select(func.count()).select_from(License)
    if status and status != "all":
        total_stmt = total_stmt.where(License.status == status)
    if search_query:
        total_stmt = total_stmt.where(License.card_code.ilike(f"%{search_query}%"))
    total = db.scalar(total_stmt) or 0

    return {
        "items": [_serialize_license(license_obj) for license_obj in items],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.post("/api/licenses", response_model=LicenseAdminResponse, status_code=201)
def api_create_license(
    payload: LicenseCreateRequest,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    service = LicenseService(db)
    try:
        license_obj = service.create_license(payload.card_code, payload.ttl_days)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except IntegrityError:
        raise HTTPException(status_code=400, detail="card_code_exists")
    return _serialize_license(license_obj)


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
    message: str | None = None,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    page = max(page, 1)
    page_size = max(1, min(page_size, MAX_PAGE_SIZE))
    search_query = q.strip() if q else None

    def apply_filters(stmt):
        if status != "all":
            stmt = stmt.where(License.status == status)
        if search_query:
            stmt = stmt.where(License.card_code.ilike(f"%{search_query}%"))
        return stmt

    total = db.scalar(apply_filters(select(func.count()).select_from(License))) or 0
    total_pages = max((total + page_size - 1) // page_size, 1) if total else 1
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * page_size

    license_stmt = apply_filters(
        select(License).order_by(License.created_at.desc()).offset(offset).limit(page_size)
    )

    license_rows = []
    for license_obj in db.scalars(license_stmt).all():
        latest_seen = None
        if license_obj.activations:
            latest_seen = max(
                (activation.last_seen for activation in license_obj.activations if activation.last_seen),
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
    status_counts = {
        row[0]: row[1]
        for row in db.execute(select(License.status, func.count()).group_by(License.status)).all()
    }

    return templates.TemplateResponse(
        request,
        "admin/licenses.html",
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
        },
    )


@router.post("/licenses/create")
def create_license_action(
    request: Request,
    card_code: Optional[str] = Form(None),
    ttl_days: int = Form(30),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    service = LicenseService(db)
    ttl_days = max(ttl_days, 0)
    try:
        license_obj = service.create_license(card_code, ttl_days)
        if license_obj.expire_at:
            expire_text = license_obj.expire_at.isoformat()
        else:
            expire_text = "永久有效"
        msg = f"已创建卡密 {license_obj.card_code}（到期：{expire_text}）"
    except ValueError as exc:
        db.rollback()
        msg = str(exc)
        license_obj = None
    except IntegrityError:
        db.rollback()
        msg = f"卡密 {card_code} 已存在"
        license_obj = None

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

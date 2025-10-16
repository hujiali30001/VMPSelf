from __future__ import annotations

import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.status import HTTP_303_SEE_OTHER, HTTP_401_UNAUTHORIZED

from app.api.deps import get_db
from app.core.settings import get_settings
from app.db import License, LicenseStatus
from app.services.license_service import LicenseService

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

DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100


def _sanitize_return_path(return_to: Optional[str]) -> str:
    if not return_to:
        return "/admin/licenses"
    if not return_to.startswith("/"):
        return "/admin/licenses"
    if not return_to.startswith("/admin"):
        return "/admin/licenses"
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
            }
        )

    statuses = [("all", "全部"), *[(s.value, STATUS_LABELS.get(s.value, s.value)) for s in LicenseStatus]]
    status_counts = {
        row[0]: row[1]
        for row in db.execute(select(License.status, func.count()).group_by(License.status)).all()
    }

    return templates.TemplateResponse(
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
    license_obj = db.scalar(select(License).where(License.card_code == card_code))
    if not license_obj:
        raise HTTPException(status_code=404, detail="license_not_found")

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

    return templates.TemplateResponse(
        "admin/license_detail.html",
        {
            "request": request,
            "license": license_obj,
            "latest_seen": latest_seen,
            "activations": activations,
            "audit_logs": audit_logs,
            "message": message,
            "status_labels": STATUS_LABELS,
            "expires_in_days": expires_in_days,
        },
    )


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

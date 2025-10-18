from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.status import HTTP_303_SEE_OTHER

from app.api.admin_portal.common import (
    AdminPrincipal,
    STATUS_LABELS,
    _append_message,
    _base_context,
    _build_audit_actor,
    _build_user_detail_context,
    _get_user_or_404,
    _sanitize_return_path,
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    require_permission,
    templates,
)
from app.api.deps import get_db
from app.db import models
from app.services.licensing import SoftwareService
from app.services.user_service import UserService

router = APIRouter(prefix="/users")


@router.get("/")
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
                    (
                        activation.last_seen or activation.activated_at
                        for activation in license_obj.activations
                    ),
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


@router.get("/{user_id}")
def user_detail_page(
    request: Request,
    user_id: int,
    message: Optional[str] = None,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("users", "view")),
):
    user = _get_user_or_404(db, user_id)
    context = _build_user_detail_context(request, user, db, message=message)
    return templates.TemplateResponse(request, "admin/users/detail.html", context)


@router.post("/register")
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


@router.post("/{user_id}/profile")
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


@router.post("/{user_id}/password")
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


@router.post("/{user_id}/delete")
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

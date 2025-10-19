from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import RedirectResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.status import HTTP_303_SEE_OTHER

from app.api.admin_portal.common import (
    AdminPrincipal,
    _admin_user_service,
    _append_message,
    _audit_service,
    _base_context,
    _format_datetime_input,
    _parse_filter_datetime,
    _sanitize_optional_str,
    _sanitize_return_path,
    require_permission,
    templates,
    settings,
)
from app.api.deps import get_db
from app.db import models
from app.services.access_control import AccessControlService
from app.services.accounts import AdminUserService, RoleService

router = APIRouter(prefix="/settings")


@router.get("/")
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
    access_service = AccessControlService(db)

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
        for value in db.scalars(
            select(models.AuditLog.module)
            .where(models.AuditLog.module.isnot(None))
            .distinct()
            .order_by(models.AuditLog.module.asc())
        ).all()
        if value
    ]

    actor_type_options = [
        value
        for value in db.scalars(
            select(models.AuditLog.actor_type)
            .where(models.AuditLog.actor_type.isnot(None))
            .distinct()
            .order_by(models.AuditLog.actor_type.asc())
        ).all()
        if value
    ]

    target_type_options = [
        value
        for value in db.scalars(
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

    cdn_manual_whitelist = access_service.list_values("cdn", "whitelist")
    cdn_blacklist = access_service.list_values("cdn", "blacklist")
    core_whitelist = access_service.list_values("core", "whitelist")
    core_blacklist = access_service.list_values("core", "blacklist")

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
        access_cdn_auto_whitelist=settings.cdn_ip_whitelist,
        access_cdn_manual_whitelist=cdn_manual_whitelist,
        access_cdn_blacklist=cdn_blacklist,
        access_core_whitelist=core_whitelist,
        access_core_blacklist=core_blacklist,
        access_cdn_ip_header=settings.cdn_ip_header,
        access_core_ip_header=settings.core_ip_header,
    )
    return templates.TemplateResponse(request, "admin/settings/index.html", context)


@router.get("/audit/export")
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


@router.post("/admins")
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


@router.post("/admins/{admin_id}/password")
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


def _parse_access_entries(raw_entries: str) -> list[str]:
    tokens: list[str] = []
    normalized = (raw_entries or "").replace("\r", "\n")
    for line in normalized.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        fragments = stripped.replace(",", " ").split()
        if not fragments:
            continue
        for fragment in fragments:
            value = fragment.strip()
            if value:
                tokens.append(value)
    return tokens


@router.post("/access/{scope}/{rule_type}")
def update_access_rules_action(
    request: Request,
    scope: str,
    rule_type: str,
    entries: str = Form(""),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("settings", "manage")),
):
    scope_key = (scope or "").strip().lower()
    rule_type_key = (rule_type or "").strip().lower()
    scope_labels = {
        "cdn": "CDN 边缘",
        "core": "主服务",
    }
    type_labels = {
        "whitelist": "白名单",
        "blacklist": "黑名单",
    }

    if scope_key not in scope_labels or rule_type_key not in type_labels:
        message = "不支持的访问控制类型"
        target = _append_message(_sanitize_return_path(return_to, fallback="/admin/settings"), message)
        return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)

    access_service = AccessControlService(db)
    values = _parse_access_entries(entries)

    try:
        access_service.bulk_replace(scope=scope_key, rule_type=rule_type_key, values=values)
    except ValueError as exc:
        db.rollback()
        error = str(exc)
        if error == "value_invalid":
            message = "存在无效的 IP 或网段，请确认格式。"
        elif error == "value_required":
            message = "请输入至少一个有效的 IP 或网段。"
        elif error == "scope_invalid":
            message = "不支持的访问控制作用域。"
        elif error == "rule_type_invalid":
            message = "不支持的访问控制类型。"
        else:
            message = f"更新失败: {exc}"
    else:
        label = f"{scope_labels[scope_key]}{type_labels[rule_type_key]}"
        if values:
            message = f"{label} 已更新，共 {len(values)} 条记录。"
        else:
            message = f"{label} 已清空。"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/settings"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@router.post("/admins/{admin_id}/status")
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

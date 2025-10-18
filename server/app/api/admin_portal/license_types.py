from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.status import HTTP_303_SEE_OTHER

from app.api.admin_portal.common import (
    AdminPrincipal,
    _append_message,
    _base_context,
    _sanitize_return_path,
    require_permission,
    templates,
)
from app.api.deps import get_db
from app.services.card_type_service import LicenseCardTypeService
from app.db import models

router = APIRouter(prefix="/license-types")


@router.get("/")
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


@router.post("/create")
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


@router.post("/{type_id}/update")
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
            target = _append_message(
                _sanitize_return_path(return_to, fallback=f"/admin/license-types?edit={type_id}"),
                message,
            )
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
            target = _append_message(
                _sanitize_return_path(return_to, fallback=f"/admin/license-types?edit={type_id}"),
                message,
            )
            return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)
    if is_active is not None:
        updates["is_active"] = bool(is_active)

    try:
        service.update_type(type_id, **updates)
    except ValueError as exc:
        db.rollback()
        message = str(exc)
    else:
        message = "类型信息已更新"

    target = _append_message(
        _sanitize_return_path(return_to, fallback=f"/admin/license-types?edit={type_id}"),
        message,
    )
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@router.post("/{type_id}/toggle")
def toggle_license_type_action(
    request: Request,
    type_id: int,
    is_active: bool = Form(False),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("license-types", "manage")),
):
    service = LicenseCardTypeService(db)
    try:
        service.set_active(type_id, is_active)
    except ValueError as exc:
        db.rollback()
        message = str(exc)
    else:
        message = "状态已更新"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/license-types"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)

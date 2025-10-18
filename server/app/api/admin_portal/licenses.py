from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import RedirectResponse, StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.status import HTTP_303_SEE_OTHER

from app.api.admin_portal.common import (
    AdminPrincipal,
    STATUS_LABELS,
    _append_message,
    _base_context,
    _build_list_query,
    _build_license_detail_context,
    _license_service,
    _sanitize_return_path,
    require_permission,
    templates,
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
)
from app.api.deps import get_db
from app.db import License, LicenseStatus, models
from app.services.audit_service import AuditService
from app.services.card_type_service import LicenseCardTypeService
from app.services.license_service import LicenseService
from app.services.software_service import SoftwareService

router = APIRouter(prefix="/licenses")


@router.get("/")
def licenses_page(
    request: Request,
    status: str = Query("all"),
    page: int = Query(1, ge=1),
    page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    q: Optional[str] = Query(None),
    message: Optional[str] = Query(None),
    type_code: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("licenses", "view")),
):
    status_filter = status.strip().lower() if status else "all"
    page = max(page, 1)
    page_size = max(1, min(page_size, MAX_PAGE_SIZE))
    offset = (page - 1) * page_size
    search_query = q.strip() if q else None
    type_query = type_code.strip() if type_code else None

    service = LicenseService(db)
    license_rows = service.list_licenses(
        status=status_filter,
        search=search_query,
        type_code=type_query,
        offset=offset,
        limit=page_size,
    )

    total_stmt = select(func.count()).select_from(License)
    if status_filter and status_filter != "all":
        total_stmt = total_stmt.where(License.status == status_filter)
    if search_query:
        total_stmt = total_stmt.where(License.card_code.ilike(f"%{search_query}%"))
    if type_query:
        total_stmt = (
            total_stmt.join_from(
                License,
                models.LicenseCardType,
                License.card_type_id == models.LicenseCardType.id,
            ).where(models.LicenseCardType.code == type_query)
        )
    total = db.scalar(total_stmt) or 0

    total_pages = max((total + page_size - 1) // page_size, 1) if total else 1
    if page > total_pages:
        page = total_pages
        offset = (page - 1) * page_size
        license_rows = service.list_licenses(
            status=status_filter,
            search=search_query,
            type_code=type_query,
            offset=offset,
            limit=page_size,
        )

    status_counts = {
        row[0]: row[1]
        for row in db.execute(select(License.status, func.count()).group_by(License.status)).all()
    }
    for status_value in LicenseStatus:
        status_counts.setdefault(status_value.value, 0)

    card_type_service = LicenseCardTypeService(db)
    card_types = card_type_service.list_types(include_inactive=True)
    active_card_types = [item for item in card_types if item.is_active]
    selected_card_type = None
    if type_query and type_query != "__none__":
        selected_card_type = next((ct for ct in card_types if ct.code == type_query), None)

    type_counts = {
        row[0]: row[1]
        for row in db.execute(
            select(License.card_type_id, func.count()).group_by(License.card_type_id)
        ).all()
    }

    def _build_type_link(code: Optional[str]) -> str:
        params = {
            "status": status_filter,
            "page": "1",
            "page_size": str(page_size),
        }
        if search_query:
            params["q"] = search_query
        if code:
            params["type_code"] = code
        return f"/admin/licenses?{urlencode(params)}"

    type_breakdown = []
    type_breakdown.append(
        {
            "code": "__all__",
            "label": "全部类型",
            "count": total,
            "is_active": True,
            "url": _build_type_link(None),
            "is_selected": not type_query or type_query == "__all__",
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
        status=status_filter,
        page=page,
        page_size=page_size,
        query=search_query or "",
        total=total,
        total_pages=total_pages,
        has_prev=page > 1,
        has_next=page < total_pages,
        prev_page=page - 1,
        next_page=page + 1,
        statuses=[
            ("all", "全部状态"),
            ("unused", "未使用"),
            ("active", "已激活"),
            ("revoked", "已撤销"),
            ("expired", "已过期"),
        ],
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


@router.post("/create")
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


@router.post("/revoke")
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
        query = _build_list_query("all", 1, DEFAULT_PAGE_SIZE, None, msg)
        target = f"/admin/licenses?{query}"
    else:
        target = _append_message(target, msg)

    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)

@router.get("/batches")
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


@router.get("/batches/{batch_id}")
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

    audit_service = AuditService(db)
    log_map: dict[int, models.AuditLog] = {}
    for license_obj in licenses:
        if license_obj.id is None:
            continue
        logs, _ = audit_service.list_logs(license_id=license_obj.id, limit=5)
        for log in logs:
            if log.id is not None:
                log_map[log.id] = log
    audit_logs = sorted(log_map.values(), key=lambda item: item.created_at, reverse=True)

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
        audit_logs=audit_logs,
    )
    return templates.TemplateResponse(request, "admin/licenses/batch_detail.html", context)


@router.get("/batches/{batch_id}/export")
def license_batch_export_page(
    batch_id: int,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("licenses", "view")),
):
    service = LicenseService(db)
    batch = service.get_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="batch_not_found")
    rows: list[list[str]] = [[
        "card_code",
        "secret",
        "status",
        "expire_at",
        "slot_code",
        "card_type",
    ]]
    for license_obj in batch.licenses:
        card_type_code = license_obj.card_type.code if license_obj.card_type else ""
        expire_at = ""
        if license_obj.expire_at:
            expire_at = license_obj.expire_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rows.append([
            license_obj.card_code,
            license_obj.secret,
            license_obj.status,
            expire_at,
            license_obj.software_slot.code if license_obj.software_slot else "",
            card_type_code,
        ])

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerows(rows)
    output.seek(0)

    filename = f"license_batch_{batch.batch_code}.csv"
    headers = {
        "Content-Disposition": f"attachment; filename={filename}",
        "Cache-Control": "no-store",
    }
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers=headers)


@router.get("/{card_code}")
def license_detail(
    request: Request,
    card_code: str,
    message: Optional[str] = None,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("licenses", "view")),
):
    license_obj = LicenseService(db).get_license(card_code)
    if not license_obj:
        raise HTTPException(status_code=404, detail="license_not_found")
    context = _build_license_detail_context(request, license_obj, db, message=message)
    return templates.TemplateResponse(request, "admin/licenses/detail.html", context)


@router.post("/{card_code}/extend")
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


@router.post("/{card_code}/offline")
def generate_offline_license_action(
    request: Request,
    card_code: str,
    fingerprint: str = Form(...),
    ttl_days: int = Form(7),
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("licenses", "manage")),
):
    license_obj = LicenseService(db).get_license(card_code)
    if not license_obj:
        raise HTTPException(status_code=404, detail="license_not_found")

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


@router.post("/{card_code}/reset")
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

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.status import HTTP_303_SEE_OTHER

from app.api.admin_portal.common import (
    AdminPrincipal,
    SOFTWARE_PACKAGE_STATUS_LABELS,
    SOFTWARE_SLOT_STATUS_LABELS,
    _append_message,
    _base_context,
    _sanitize_return_path,
    require_permission,
    templates,
)
from app.api.deps import get_db
from app.db import SoftwareSlotStatus
from app.services.software_service import SoftwareService

router = APIRouter(prefix="/software")


@router.get("/")
def software_page(
    request: Request,
    message: Optional[str] = None,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("software", "view")),
):
    service = SoftwareService(db)
    slots = service.list_slots()

    slot_rows: list[dict[str, object]] = []
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


@router.post("/slots")
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


@router.post("/slots/{slot_id}/status")
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


@router.post("/slots/{slot_id}/packages")
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


@router.post("/packages/{package_id}/promote")
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


@router.post("/packages/{package_id}/retire")
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

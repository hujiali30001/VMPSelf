from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.status import HTTP_303_SEE_OTHER

from app.api.admin_portal.common import (
    AdminPrincipal,
    CDN_STATUS_LABELS,
    CDN_TASK_STATUS_LABELS,
    _append_message,
    _base_context,
    _sanitize_return_path,
    require_permission,
    templates,
)
from app.api.deps import get_db
from app.db import CDNEndpointStatus, CDNTaskType
from app.services.cdn_service import CDNService

router = APIRouter(prefix="/cdn")


@router.get("/")
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

    task_rows: list[dict[str, object]] = []
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


@router.post("/endpoints")
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


@router.post("/endpoints/{endpoint_id}/status")
def update_cdn_endpoint_status_action(
    request: Request,
    endpoint_id: int,
    status: str = Form(...),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("cdn", "manage")),
):
    service = CDNService(db)
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


@router.post("/endpoints/{endpoint_id}/tasks")
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

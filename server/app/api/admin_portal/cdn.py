from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.status import HTTP_303_SEE_OTHER

from app.api.admin_portal.common import (
    AdminPrincipal,
    CDN_HEALTH_STATUS_LABELS,
    CDN_STATUS_LABELS,
    CDN_TASK_STATUS_LABELS,
    _append_message,
    _base_context,
    _sanitize_return_path,
    require_permission,
    templates,
)
from app.api.deps import get_db
from app.db import CDNEndpointStatus, CDNHealthStatus, CDNTaskType
from app.services.cdn import CDNService, DeploymentError

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
    health_counts: dict[str, int] = {
        CDNHealthStatus.HEALTHY.value: 0,
        CDNHealthStatus.DEGRADED.value: 0,
        CDNHealthStatus.UNHEALTHY.value: 0,
        CDNHealthStatus.UNKNOWN.value: 0,
    }

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

        health_state = endpoint.health_status or CDNHealthStatus.UNKNOWN.value
        if health_state not in health_counts:
            health_state = CDNHealthStatus.UNKNOWN.value
        health_counts[health_state] = health_counts.get(health_state, 0) + 1

        last_deployment = endpoint.deployments[0] if endpoint.deployments else None
        last_health = endpoint.health_checks[0] if endpoint.health_checks else None

        endpoint_rows.append(
            {
                "endpoint": endpoint,
                "last_task": last_task,
                "task_count": len(endpoint.tasks or []),
                "last_deployment": last_deployment,
                "last_health": last_health,
            }
        )

    task_type_labels = {
        CDNTaskType.PURGE.value: "刷新缓存",
        CDNTaskType.PREFETCH.value: "预取内容",
        CDNTaskType.DEPLOY.value: "节点部署",
    }

    task_rows: list[dict[str, object]] = []
    for task in tasks:
        task_rows.append(
            {
                "task": task,
                "endpoint": getattr(task, "endpoint", None),
                "task_label": task_type_labels.get(task.task_type, task.task_type),
            }
        )

    health_stats = [
        {
            "status": status,
            "label": CDN_HEALTH_STATUS_LABELS.get(status, status),
            "count": health_counts.get(status, 0),
        }
        for status in (
            CDNHealthStatus.HEALTHY.value,
            CDNHealthStatus.DEGRADED.value,
            CDNHealthStatus.UNHEALTHY.value,
            CDNHealthStatus.UNKNOWN.value,
        )
    ]

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
        health_stats=health_stats,
        tasks=task_rows,
        status_labels=CDN_STATUS_LABELS,
        health_status_labels=CDN_HEALTH_STATUS_LABELS,
        task_status_labels=CDN_TASK_STATUS_LABELS,
        task_types=[
            (CDNTaskType.PURGE.value, "刷新缓存"),
            (CDNTaskType.PREFETCH.value, "预取内容"),
        ],
        task_type_labels=task_type_labels,
    )
    return templates.TemplateResponse(request, "admin/cdn/index.html", context)


@router.post("/endpoints")
def create_cdn_endpoint_action(
    request: Request,
    name: str = Form(...),
    domain: str = Form(...),
    provider: str = Form(...),
    origin: str = Form(...),
    host: str = Form(...),
    ssh_username: str = Form(...),
    ssh_password: Optional[str] = Form(None),
    ssh_private_key: Optional[str] = Form(None),
    ssh_port: int = Form(22),
    listen_port: int = Form(443),
    origin_port: int = Form(443),
    deployment_mode: str = Form("http"),
    edge_token: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("cdn", "manage")),
):
    service = CDNService(db)
    try:
        service.create_endpoint(
            name=name,
            domain=domain,
            provider=provider,
            origin=origin,
            host=host,
            ssh_username=ssh_username,
            ssh_password=ssh_password,
            ssh_private_key=ssh_private_key,
            ssh_port=ssh_port,
            listen_port=listen_port,
            origin_port=origin_port,
            deployment_mode=deployment_mode,
            edge_token=edge_token,
            notes=notes,
        )
    except ValueError as exc:
        db.rollback()
        error_map = {
            "name_too_short": "名称至少需要 3 个字符",
            "domain_invalid": "域名格式不正确",
            "provider_required": "请选择或填写加速服务提供商",
            "origin_required": "请填写源站地址",
            "domain_exists": "域名已存在，请勿重复添加",
            "host_required": "请填写节点公网 IP 或域名",
            "ssh_username_required": "请填写 SSH 登录用户名",
            "port_invalid": "端口号无效，请检查输入",
            "deployment_mode_invalid": "部署模式仅支持 HTTP 或 TCP",
        }
        message = error_map.get(str(exc), f"创建失败: {exc}")
    else:
        message = "已创建新的 CDN 节点"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/cdn"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)


@router.post("/endpoints/{endpoint_id}/deploy")
def deploy_cdn_endpoint_action(
    request: Request,
    endpoint_id: int,
    allow_http: Optional[str] = Form(None),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("cdn", "manage")),
):
    service = CDNService(db)
    allow_http_flag = False
    if allow_http:
        allow_http_flag = allow_http.lower() in {"1", "true", "on", "yes"}

    try:
        service.deploy_endpoint(endpoint_id, allow_http=allow_http_flag)
    except ValueError as exc:
        db.rollback()
        if str(exc) == "endpoint_not_found":
            message = "未找到指定的 CDN 节点"
        else:
            message = f"部署失败: {exc}"
    except DeploymentError as exc:
        db.rollback()
        message = f"部署执行失败: {exc}"
    else:
        message = "节点已部署并更新配置"

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


@router.post("/endpoints/{endpoint_id}/health-check")
def run_cdn_health_check_action(
    request: Request,
    endpoint_id: int,
    protocol: Optional[str] = Form(None),
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("cdn", "manage")),
):
    service = CDNService(db)
    normalized_protocol = (protocol or "").strip().lower() or None

    try:
        record = service.run_health_check(endpoint_id, protocol=normalized_protocol)
    except ValueError as exc:
        db.rollback()
        error = str(exc)
        if error == "endpoint_not_found":
            message = "未找到指定的 CDN 节点"
        elif error in {"health_protocol_invalid", "health_protocol_unsupported"}:
            message = "健康检查协议无效或当前节点不支持"
        else:
            message = f"探测失败: {exc}"
    else:
        label = CDN_HEALTH_STATUS_LABELS.get(record.status, record.status)
        latency_note = f" · {record.latency_ms} ms" if record.latency_ms is not None else ""
        message = f"健康检查完成：{label}{latency_note}"

    target = _append_message(_sanitize_return_path(return_to, fallback="/admin/cdn"), message)
    return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.api.admin_portal.common import (
    AdminPrincipal,
    STATUS_LABELS,
    _base_context,
    _serialize_license,
    _serialize_user,
    require_permission,
    templates,
)
from app.api.deps import get_db
from app.db import License, LicenseStatus, models
from sqlalchemy.orm import Session

router = APIRouter()


@router.get("/")
def dashboard_page(
    request: Request,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("dashboard", "view")),
):
    total_users = db.scalar(select(func.count()).select_from(models.User)) or 0
    total_licenses = db.scalar(select(func.count()).select_from(License)) or 0
    total_card_types = db.scalar(select(func.count()).select_from(models.LicenseCardType)) or 0
    active_card_types = (
        db.scalar(
            select(func.count())
            .select_from(models.LicenseCardType)
            .where(models.LicenseCardType.is_active.is_(True))
        )
        or 0
    )
    total_activations = db.scalar(select(func.count()).select_from(models.Activation)) or 0

    status_rows = db.execute(select(License.status, func.count()).group_by(License.status)).all()
    status_counts = {status: count for status, count in status_rows}
    for status in LicenseStatus:
        status_counts.setdefault(status.value, 0)

    now = datetime.now(timezone.utc)
    upcoming = now + timedelta(days=7)

    recent_users_stmt = (
        select(models.User)
        .options(selectinload(models.User.license))
        .order_by(models.User.created_at.desc())
        .limit(6)
    )
    recent_users = [
        user_data
        for user_data in (_serialize_user(user) for user in db.execute(recent_users_stmt).scalars().all())
        if user_data
    ]

    recent_licenses_stmt = (
        select(License)
        .options(selectinload(License.user), selectinload(License.card_type))
        .order_by(License.created_at.desc())
        .limit(6)
    )
    recent_licenses = [
        license_data
        for license_data in (
            _serialize_license(license_obj)
            for license_obj in db.execute(recent_licenses_stmt).scalars().all()
        )
        if license_data
    ]

    expiring_soon_stmt = (
        select(License)
        .options(selectinload(License.user), selectinload(License.card_type))
        .where(
            License.expire_at.isnot(None),
            License.expire_at > now,
            License.expire_at <= upcoming,
        )
        .order_by(License.expire_at.asc())
        .limit(5)
    )
    expiring_licenses = [
        license_data
        for license_data in (
            _serialize_license(license_obj)
            for license_obj in db.execute(expiring_soon_stmt).scalars().all()
        )
        if license_data
    ]

    overall_stats = [
        {"code": "users", "label": "注册用户", "value": total_users},
        {"code": "licenses", "label": "卡密总量", "value": total_licenses},
        {
            "code": "active-licenses",
            "label": "激活中的卡密",
            "value": status_counts.get(LicenseStatus.ACTIVE.value, 0),
        },
        {"code": "activations", "label": "激活设备", "value": total_activations},
        {
            "code": "card-types",
            "label": "启用卡密类型",
            "value": active_card_types,
            "meta": f"共 {total_card_types} 种",
        },
    ]

    status_summary = [
        {
            "code": status.value,
            "label": STATUS_LABELS.get(status.value, status.value),
            "count": status_counts.get(status.value, 0),
        }
        for status in LicenseStatus
    ]

    module_cards = [
        {
            "code": "users",
            "label": "用户中心",
            "description": "管理注册账号、关联卡密与安全操作。",
            "href": "/admin/users",
            "ready": True,
        },
        {
            "code": "licenses",
            "label": "卡密管理",
            "description": "创建卡密、筛选状态并快速跳转详情页。",
            "href": "/admin/licenses",
            "ready": True,
        },
        {
            "code": "license-types",
            "label": "卡密类型",
            "description": "维护卡密模板、默认时长与前缀策略。",
            "href": "/admin/license-types",
            "ready": True,
        },
        {
            "code": "cdn",
            "label": "CDN 管理",
            "description": "配置源站防护、共享密钥与 IP 白名单。",
            "href": "/admin/cdn",
            "ready": True,
        },
        {
            "code": "software",
            "label": "软件位",
            "description": "上传保护壳、分配发布渠道与配额。",
            "href": "/admin/software",
            "ready": True,
        },
        {
            "code": "settings",
            "label": "系统设置",
            "description": "调整后台安全策略、审计与管理员账号。",
            "href": "/admin/settings",
            "ready": True,
        },
    ]

    context = _base_context(
        request,
        page_title="控制台总览",
        page_subtitle="统一入口集中管理授权服务核心模块。",
        page_description="综合查看用户、卡密与即将过期的关键指标。",
        active_page="dashboard",
        stats=overall_stats,
        status_summary=status_summary,
        module_cards=module_cards,
        recent_users=recent_users,
        recent_licenses=recent_licenses,
        expiring_licenses=expiring_licenses,
        status_counts=status_counts,
        total_card_types=total_card_types,
        timeframe_days=7,
        now=now,
        status_labels=STATUS_LABELS,
    )

    return templates.TemplateResponse(
        request,
        "admin/dashboard/index.html",
        context,
    )

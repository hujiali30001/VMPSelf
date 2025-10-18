from __future__ import annotations

from pathlib import Path
from typing import Dict, Tuple

from fastapi.security import HTTPBasic
from fastapi.templating import Jinja2Templates

from app.core.settings import get_settings
from app.db import (
    CDNEndpointStatus,
    CDNHealthStatus,
    CDNTaskStatus,
    LicenseStatus,
    SoftwarePackageStatus,
    SoftwareSlotStatus,
)

settings = get_settings()
basic_auth = HTTPBasic()
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[3] / "templates"))

STATUS_LABELS = {
    LicenseStatus.UNUSED.value: "未使用",
    LicenseStatus.ACTIVE.value: "已激活",
    LicenseStatus.REVOKED.value: "已撤销",
    LicenseStatus.EXPIRED.value: "已过期",
}

CDN_STATUS_LABELS = {
    CDNEndpointStatus.ACTIVE.value: "活跃",
    CDNEndpointStatus.PAUSED.value: "已暂停",
    CDNEndpointStatus.ERROR.value: "异常",
}

CDN_TASK_STATUS_LABELS = {
    CDNTaskStatus.PENDING.value: "排队中",
    CDNTaskStatus.COMPLETED.value: "已完成",
    CDNTaskStatus.FAILED.value: "失败",
}

CDN_HEALTH_STATUS_LABELS = {
    CDNHealthStatus.HEALTHY.value: "健康",
    CDNHealthStatus.DEGRADED.value: "降级",
    CDNHealthStatus.UNHEALTHY.value: "异常",
    CDNHealthStatus.UNKNOWN.value: "未知",
}

SOFTWARE_SLOT_STATUS_LABELS = {
    SoftwareSlotStatus.ACTIVE.value: "上线中",
    SoftwareSlotStatus.PAUSED.value: "暂停",
}

SOFTWARE_PACKAGE_STATUS_LABELS = {
    SoftwarePackageStatus.DRAFT.value: "草稿",
    SoftwarePackageStatus.ACTIVE.value: "已上线",
    SoftwarePackageStatus.RETIRED.value: "已下线",
}

DEFAULT_NAV_ITEMS: Tuple[dict[str, str], ...] = (
    {"code": "dashboard", "label": "总览", "href": "/admin"},
    {"code": "licenses", "label": "卡密列表", "href": "/admin/licenses"},
    {"code": "license-types", "label": "卡密类型", "href": "/admin/license-types"},
    {"code": "users", "label": "用户管理", "href": "/admin/users"},
    {"code": "software", "label": "软件位", "href": "/admin/software"},
    {"code": "cdn", "label": "CDN 管理", "href": "/admin/cdn"},
    {"code": "settings", "label": "系统设置", "href": "/admin/settings"},
)

NAV_PERMISSION_REQUIREMENTS: Dict[str, Tuple[str, str]] = {
    "dashboard": ("dashboard", "view"),
    "licenses": ("licenses", "view"),
    "license-types": ("license-types", "view"),
    "users": ("users", "view"),
    "software": ("software", "view"),
    "cdn": ("cdn", "view"),
    "settings": ("settings", "view"),
}

__all__ = [
    "settings",
    "basic_auth",
    "templates",
    "STATUS_LABELS",
    "CDN_STATUS_LABELS",
    "CDN_HEALTH_STATUS_LABELS",
    "CDN_TASK_STATUS_LABELS",
    "SOFTWARE_SLOT_STATUS_LABELS",
    "SOFTWARE_PACKAGE_STATUS_LABELS",
    "DEFAULT_NAV_ITEMS",
    "NAV_PERMISSION_REQUIREMENTS",
]

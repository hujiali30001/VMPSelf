from __future__ import annotations

from app.api.admin_portal import router
from app.api.admin_portal.common import require_admin, require_permission

__all__ = ["router", "require_admin", "require_permission"]

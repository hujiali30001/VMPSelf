from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, List, Optional
"""Backward-compatible import for AdminUserService.

The service has moved to ``app.services.accounts.admin``. Import from
``app.services.accounts`` instead of this module for new code.
"""

from __future__ import annotations

from app.services.accounts import AdminUserService

__all__ = ["AdminUserService"]
class AdminUserService:

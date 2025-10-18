"""Backward-compatible import for RoleService.

The service now lives in ``app.services.accounts.roles``. Update imports to
``app.services.accounts`` when possible.
"""

from __future__ import annotations

from app.services.accounts import RoleService

__all__ = ["RoleService"]

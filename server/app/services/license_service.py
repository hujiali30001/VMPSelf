from __future__ import annotations

"""Backward-compatible import for LicenseService.

The full implementation resides in ``app.services.licensing.licenses``.
"""

from app.services.licensing import LicenseService

__all__ = ["LicenseService"]

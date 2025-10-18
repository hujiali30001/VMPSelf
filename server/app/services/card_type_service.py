from __future__ import annotations

"""Backward-compatible import for LicenseCardTypeService.

The implementation moved to ``app.services.licensing.card_types``.
"""

from app.services.licensing import LicenseCardTypeService

__all__ = ["LicenseCardTypeService"]

from __future__ import annotations

"""Backward-compatible import for SoftwareService.

Use ``app.services.licensing.software`` instead.
"""

from app.services.licensing import SoftwareService

__all__ = ["SoftwareService"]

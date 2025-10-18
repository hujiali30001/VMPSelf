from __future__ import annotations

"""Backward-compatible import for AuditService utilities.

The service and value objects now live in ``app.services.audit.service``.
"""

from app.services.audit import AuditActor, AuditService, AuditTarget

__all__ = ["AuditService", "AuditActor", "AuditTarget"]

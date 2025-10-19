from __future__ import annotations

import logging
from typing import Optional

import anyio

from app.db import AccessScope
from app.db.session import SessionLocal
from app.services.access_control import AccessControlService

logger = logging.getLogger("access_control")


def _sync_auto_blacklist(scope: AccessScope | str, ip: str, reason: Optional[str]) -> None:
    with SessionLocal() as session:
        service = AccessControlService(session)
        service.ensure_blacklist_entry(scope=scope, ip=ip, reason=reason)


async def auto_blacklist_ip(
    scope: AccessScope | str,
    ip: Optional[str],
    *,
    reason: Optional[str] = None,
) -> None:
    if not ip:
        return

    try:
        await anyio.to_thread.run_sync(_sync_auto_blacklist, scope, ip, reason)
    except ValueError as exc:
        code = exc.args[0] if exc.args else None
        if code in {"value_invalid", "value_required", "scope_invalid"}:
            logger.debug(
                "Skip auto blacklist due to invalid input",
                extra={"scope": str(scope), "ip": ip, "reason": reason, "code": code},
            )
            return
        logger.exception(
            "Failed to auto blacklist IP",
            extra={"scope": str(scope), "ip": ip, "reason": reason, "code": code},
        )
    except Exception:  # pragma: no cover - defensive
        logger.exception(
            "Failed to auto blacklist IP",
            extra={"scope": str(scope), "ip": ip, "reason": reason},
        )

from __future__ import annotations

import hmac
import logging
from typing import Callable, Iterable, Optional, Sequence, Set

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.ip_access import evaluate_ip_access

logger = logging.getLogger("cdn_guard")


class CDNGuardMiddleware(BaseHTTPMiddleware):
    """Restrict access to requests that pass through an authenticated CDN edge."""

    def __init__(
        self,
        app,
        *,
        header_name: str,
        shared_token: str,
        allow_paths: Iterable[str] | None = None,
        ip_header: Optional[str] = None,
        ip_whitelist: Iterable[str] | None = None,
        ip_blacklist: Iterable[str] | None = None,
        dynamic_whitelist: Optional[Callable[[], Sequence[str]]] = None,
        dynamic_blacklist: Optional[Callable[[], Sequence[str]]] = None,
    ) -> None:
        super().__init__(app)
        self.header_name = header_name
        self.shared_token = shared_token
        self.allow_paths: Set[str] = {path.rstrip("/") or "/" for path in (allow_paths or [])}
        self.ip_header = ip_header
        self._static_whitelist: Set[str] = {ip.strip() for ip in (ip_whitelist or []) if ip.strip()}
        self._static_blacklist: Set[str] = {ip.strip() for ip in (ip_blacklist or []) if ip.strip()}
        self._dynamic_whitelist = dynamic_whitelist
        self._dynamic_blacklist = dynamic_blacklist

    def _requires_ip_check(self) -> bool:
        return bool(
            self._static_whitelist
            or self._static_blacklist
            or self._dynamic_whitelist
            or self._dynamic_blacklist
        )

    def _collect_entries(
        self,
        static_entries: Set[str],
        dynamic_provider: Optional[Callable[[], Sequence[str]]],
    ) -> Sequence[str]:
        values = set(static_entries)
        if dynamic_provider:
            try:
                dynamic_values = dynamic_provider() or []
            except Exception:  # pragma: no cover - defensive
                logger.exception("Failed to load dynamic CDN access rules")
                dynamic_values = []
            values.update(entry.strip() for entry in dynamic_values if entry and entry.strip())
        return sorted(values)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path.rstrip("/") or "/"
        if path in self.allow_paths:
            return await call_next(request)

        token = request.headers.get(self.header_name)
        if not token or not hmac.compare_digest(token, self.shared_token):
            logger.warning("CDNGuard blocked request without valid token", extra={"path": path})
            return JSONResponse(status_code=403, content={"detail": "origin_forbidden"})

        if self._requires_ip_check():
            if not self.ip_header:
                logger.warning(
                    "CDNGuard IP enforcement skipped due to missing ip_header configuration",
                    extra={"path": path},
                )
                return JSONResponse(status_code=403, content={"detail": "origin_forbidden"})

            forwarded = request.headers.get(self.ip_header, "")
            client_ip = forwarded.split(",")[0].strip()
            whitelist_entries = self._collect_entries(self._static_whitelist, self._dynamic_whitelist)
            blacklist_entries = self._collect_entries(self._static_blacklist, self._dynamic_blacklist)
            allowed, reason = evaluate_ip_access(client_ip, whitelist_entries, blacklist_entries)
            if not allowed:
                logger.warning(
                    "CDNGuard blocked request due to access rules",
                    extra={
                        "path": path,
                        "client_ip": client_ip or None,
                        "reason": reason,
                    },
                )
                return JSONResponse(status_code=403, content={"detail": "origin_forbidden"})
            request.state.cdn_client_ip = client_ip

        request.state.cdn_verified = True
        return await call_next(request)

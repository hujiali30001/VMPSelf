from __future__ import annotations

import hmac
import logging
from typing import Iterable, Optional, Set

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

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
    ) -> None:
        super().__init__(app)
        self.header_name = header_name
        self.shared_token = shared_token
        self.allow_paths: Set[str] = {path.rstrip("/") or "/" for path in (allow_paths or [])}
        self.ip_header = ip_header
        self.ip_whitelist: Set[str] = {ip.strip() for ip in (ip_whitelist or []) if ip.strip()}

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path.rstrip("/") or "/"
        if path in self.allow_paths:
            return await call_next(request)

        token = request.headers.get(self.header_name)
        if not token or not hmac.compare_digest(token, self.shared_token):
            logger.warning("CDNGuard blocked request without valid token", extra={"path": path})
            return JSONResponse(status_code=403, content={"detail": "origin_forbidden"})

        if self.ip_whitelist and self.ip_header:
            forwarded = request.headers.get(self.ip_header, "")
            client_ip = forwarded.split(",")[0].strip()
            if client_ip not in self.ip_whitelist:
                logger.warning(
                    "CDNGuard blocked request with untrusted IP",
                    extra={"path": path, "client_ip": client_ip},
                )
                return JSONResponse(status_code=403, content={"detail": "origin_forbidden"})
            request.state.cdn_client_ip = client_ip

        request.state.cdn_verified = True
        return await call_next(request)

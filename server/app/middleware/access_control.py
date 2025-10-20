from __future__ import annotations

import logging
from typing import Callable, Iterable, Optional, Sequence, Set

import ipaddress

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.ip_access import evaluate_ip_access
from app.db import AccessScope
from app.services.auto_blacklist import auto_blacklist_ip

logger = logging.getLogger("access_control")


class AccessControlMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        *,
        allow_paths: Optional[Iterable[str]] = None,
        ip_header: Optional[str] = None,
        static_whitelist: Optional[Iterable[str]] = None,
        static_blacklist: Optional[Iterable[str]] = None,
        dynamic_whitelist: Optional[Callable[[], Sequence[str]]] = None,
        dynamic_blacklist: Optional[Callable[[], Sequence[str]]] = None,
    ) -> None:
        super().__init__(app)
        self.allow_paths: Set[str] = {path.rstrip("/") or "/" for path in (allow_paths or [])}
        self.ip_header = ip_header
        self._static_whitelist: Set[str] = {entry.strip() for entry in (static_whitelist or []) if entry and entry.strip()}
        self._static_blacklist: Set[str] = {entry.strip() for entry in (static_blacklist or []) if entry and entry.strip()}
        self._dynamic_whitelist = dynamic_whitelist
        self._dynamic_blacklist = dynamic_blacklist

    def _requires_check(self) -> bool:
        return bool(
            self._static_whitelist
            or self._static_blacklist
            or self._dynamic_whitelist
            or self._dynamic_blacklist
        )

    def _collect_entries(
        self,
        static_entries: Set[str],
        provider: Optional[Callable[[], Sequence[str]]],
    ) -> Sequence[str]:
        values = set(static_entries)
        if provider:
            try:
                entries = provider() or []
            except Exception:  # pragma: no cover - defensive
                logger.exception("Failed to resolve dynamic access control entries")
                entries = []
            values.update(entry.strip() for entry in entries if entry and entry.strip())
        return sorted(values)

    def _extract_client_ip(self, request: Request) -> Optional[str]:
        forwarded_value: Optional[str] = None
        if self.ip_header:
            forwarded_value = request.headers.get(self.ip_header, "")
            if forwarded_value:
                return forwarded_value.split(",")[0].strip()

        client = request.client
        if client and client.host:
            candidate = client.host.strip()
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                if candidate.lower() in {"localhost", "testclient"}:
                    return "127.0.0.1"

        if forwarded_value:
            candidate = forwarded_value.split(",")[0].strip()
            if candidate:
                try:
                    ipaddress.ip_address(candidate)
                    return candidate
                except ValueError:
                    if candidate.lower() in {"localhost", "testclient"}:
                        return "127.0.0.1"

        return None

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path.rstrip("/") or "/"
        if path in self.allow_paths or not self._requires_check():
            return await call_next(request)

        client_ip = self._extract_client_ip(request)
        whitelist_entries = self._collect_entries(self._static_whitelist, self._dynamic_whitelist)
        blacklist_entries = self._collect_entries(self._static_blacklist, self._dynamic_blacklist)

        allowed, reason = evaluate_ip_access(client_ip, whitelist_entries, blacklist_entries)
        if not allowed:
            if client_ip and reason not in {"blacklist", "ip_missing", "ip_invalid"}:
                await auto_blacklist_ip(AccessScope.CORE, client_ip, reason=reason or "denied")
            logger.warning(
                "Access control blocked request",
                extra={
                    "path": path,
                    "client_ip": client_ip or None,
                    "reason": reason,
                },
            )
            return JSONResponse(status_code=403, content={"detail": "access_denied"})

        request.state.client_ip = client_ip
        return await call_next(request)

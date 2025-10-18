from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
import socket
import ssl
import time

import httpx

from app.db import CDNHealthStatus


@dataclass
class HealthCheckResult:
    status: CDNHealthStatus
    protocol: str
    latency_ms: Optional[int]
    status_code: Optional[int]
    message: Optional[str]
    checked_at: datetime


class CDNHealthChecker:
    """Perform on-demand health probes for CDN endpoints."""

    def __init__(self, *, timeout: float = 5.0, verify_tls: bool = False) -> None:
        self.timeout = timeout
        self.verify_tls = verify_tls

    def check_http(self, host: str, port: int, *, use_https: bool = True, path: str = "/") -> HealthCheckResult:
        scheme = "https" if use_https else "http"
        url = f"{scheme}://{host}:{port}{path}"
        started = time.perf_counter()
        try:
            with httpx.Client(timeout=self.timeout, verify=self.verify_tls) as client:
                response = client.head(url, follow_redirects=True)
            latency_ms = int((time.perf_counter() - started) * 1000)
            status = CDNHealthStatus.HEALTHY if response.status_code < 500 else CDNHealthStatus.DEGRADED
            message = f"HTTP {response.status_code}"
            if response.status_code >= 500:
                message = f"上游返回 {response.status_code}"
            return HealthCheckResult(
                status=status,
                protocol="https" if use_https else "http",
                latency_ms=latency_ms,
                status_code=response.status_code,
                message=message,
                checked_at=datetime.now(timezone.utc),
            )
        except httpx.TimeoutException:
            return HealthCheckResult(
                status=CDNHealthStatus.UNHEALTHY,
                protocol="https" if use_https else "http",
                latency_ms=None,
                status_code=None,
                message="请求超时",
                checked_at=datetime.now(timezone.utc),
            )
        except httpx.HTTPError as exc:  # pragma: no cover - defensive
            return HealthCheckResult(
                status=CDNHealthStatus.UNHEALTHY,
                protocol="https" if use_https else "http",
                latency_ms=None,
                status_code=None,
                message=f"HTTP 请求失败: {exc}",
                checked_at=datetime.now(timezone.utc),
            )

    def check_tcp(self, host: str, port: int) -> HealthCheckResult:
        started = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                # Explicitly wrap with SSL if the port likely expects TLS so we can detect handshake issues.
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with context.wrap_socket(sock, server_hostname=host):
                        pass
                except ssl.SSLError:
                    # Not all TCP services speak TLS; ignore handshake failures.
                    pass
            latency_ms = int((time.perf_counter() - started) * 1000)
            return HealthCheckResult(
                status=CDNHealthStatus.HEALTHY,
                protocol="tcp",
                latency_ms=latency_ms,
                status_code=None,
                message="TCP 三次握手成功",
                checked_at=datetime.now(timezone.utc),
            )
        except (socket.timeout, TimeoutError):
            return HealthCheckResult(
                status=CDNHealthStatus.UNHEALTHY,
                protocol="tcp",
                latency_ms=None,
                status_code=None,
                message="TCP 连接超时",
                checked_at=datetime.now(timezone.utc),
            )
        except OSError as exc:
            return HealthCheckResult(
                status=CDNHealthStatus.UNHEALTHY,
                protocol="tcp",
                latency_ms=None,
                status_code=None,
                message=f"TCP 连接失败: {exc}",
                checked_at=datetime.now(timezone.utc),
            )


__all__ = ["CDNHealthChecker", "HealthCheckResult"]

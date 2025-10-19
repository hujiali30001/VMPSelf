from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import logging
import os
import socket
from pathlib import Path
from typing import Any, Iterable, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.crypto import decrypt_secret, encrypt_secret
from app.core.settings import get_settings
from app.db import (
    CDNDeployment,
    CDNEndpoint,
    CDNEndpointPort,
    CDNEndpointStatus,
    CDNHealthCheck,
    CDNHealthStatus,
    CDNTask,
    CDNTaskStatus,
    CDNTaskType,
)
from app.services.cdn.deployer import (
    CDNDeployer,
    DeploymentConfig,
    DeploymentError,
    DeploymentTarget,
    PortMapping,
    generate_nginx_config,
)
from app.services.cdn.health import CDNHealthChecker, HealthCheckResult


logger = logging.getLogger(__name__)


def _parse_optional_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"", "null", "none"}:
        return None
    return text in {"1", "true", "yes", "on"}


def _serialize_port_mappings(mappings: Iterable[PortMapping]) -> list[dict[str, Any]]:
    return [
        {
            "listen_port": mapping.listen_port,
            "origin_port": mapping.origin_port,
            "allow_http": mapping.allow_http,
        }
        for mapping in mappings
    ]


@dataclass
class EndpointCredentials:
    host: str
    ssh_username: str
    ssh_port: int
    ssh_password: Optional[str]
    ssh_private_key: Optional[str]
    sudo_password: Optional[str]


class CDNService:
    def __init__(
        self,
        db: Session,
        *,
        deployer: Optional[CDNDeployer] = None,
        health_checker: Optional[CDNHealthChecker] = None,
    ) -> None:
        self.db = db
        self.deployer = deployer or CDNDeployer()
        self.health_checker = health_checker or CDNHealthChecker()

    @staticmethod
    def _build_port_mappings_payload(
        deployment_mode: str,
        listen_port: int,
        origin_port: int,
        payloads: Optional[Iterable[dict[str, Any] | PortMapping]],
        *,
        allow_http_flag: bool,
    ) -> tuple[list[PortMapping], bool]:
        if not payloads:
            return ([], allow_http_flag)

        result: list[PortMapping] = []
        effective_allow_http = allow_http_flag

        for item in payloads:
            if item is None:
                continue
            if isinstance(item, PortMapping):
                allow_http_value = item.allow_http
                if allow_http_value:
                    effective_allow_http = True
                result.append(item)
                continue

            listen_value = item.get("listen_port")
            origin_value = item.get("origin_port")
            if listen_value in (None, "", "-") or origin_value in (None, "", "-"):
                continue

            allow_http_value = _parse_optional_bool(item.get("allow_http"))
            if allow_http_value:
                effective_allow_http = True

            result.append(
                PortMapping(
                    listen_port=listen_value,
                    origin_port=origin_value if origin_value is not None else origin_port,
                    allow_http=allow_http_value,
                )
            )

        if deployment_mode != "http":
            effective_allow_http = False

        return (result, effective_allow_http)

    @staticmethod
    def _apply_port_mappings(endpoint: CDNEndpoint, mode: str, mappings: list[PortMapping]) -> None:
        sorted_mappings = sorted(mappings, key=lambda item: (int(item.listen_port), int(item.origin_port)))
        endpoint.port_mappings.clear()
        for mapping in sorted_mappings:
            endpoint.port_mappings.append(
                CDNEndpointPort(
                    listen_port=int(mapping.listen_port),
                    origin_port=int(mapping.origin_port),
                    allow_http=mapping.allow_http if mode == "http" else None,
                )
            )

        if sorted_mappings:
            endpoint.listen_port = int(sorted_mappings[0].listen_port)
            endpoint.origin_port = int(sorted_mappings[0].origin_port)

    def _build_deployment_config_from_endpoint(
        self,
        endpoint: CDNEndpoint,
        *,
        allow_http_override: Optional[bool] = None,
    ) -> DeploymentConfig:
        if endpoint.deployment_mode == "http":
            if allow_http_override is None:
                allow_http_value = any(p.allow_http for p in endpoint.port_mappings)
            else:
                allow_http_value = allow_http_override
        else:
            allow_http_value = False

        config = DeploymentConfig(
            origin_host=endpoint.origin,
            origin_port=endpoint.origin_port,
            listen_port=endpoint.listen_port,
            edge_token=endpoint.edge_token,
            mode=endpoint.deployment_mode,
            allow_http=allow_http_value,
            proxy_protocol=endpoint.proxy_protocol_enabled if endpoint.deployment_mode == "tcp" else False,
        )

        if endpoint.port_mappings:
            config.port_mappings = [
                PortMapping(
                    listen_port=port.listen_port,
                    origin_port=port.origin_port,
                    allow_http=port.allow_http,
                )
                for port in sorted(endpoint.port_mappings, key=lambda item: (item.listen_port, item.id or 0))
            ]

        if config.mode == "http" and config.allow_http and not any(mp.allow_http for mp in config.port_mappings):
            fallback_listen = 80 if config.listen_port != 80 else config.listen_port
            config.port_mappings.append(
                PortMapping(listen_port=fallback_listen, origin_port=config.origin_port, allow_http=True)
            )

        config.normalize()
        return config

    # Endpoints -----------------------------------------------------------------
    def list_endpoints(self) -> List[CDNEndpoint]:
        stmt = (
            select(CDNEndpoint)
            .options(
                selectinload(CDNEndpoint.tasks),
                selectinload(CDNEndpoint.deployments),
                selectinload(CDNEndpoint.health_checks),
                selectinload(CDNEndpoint.port_mappings),
            )
            .order_by(CDNEndpoint.created_at.desc())
        )
        return list(self.db.scalars(stmt).all())

    def get_endpoint(self, endpoint_id: int) -> Optional[CDNEndpoint]:
        return self.db.get(CDNEndpoint, endpoint_id)

    def create_endpoint(
        self,
        *,
        name: str,
        domain: str,
        provider: str,
        origin: str,
        host: str,
        ssh_username: str,
        ssh_password: Optional[str] = None,
        ssh_private_key: Optional[str] = None,
    sudo_password: Optional[str] = None,
        ssh_port: int = 22,
        listen_port: int = 443,
        origin_port: int = 443,
        deployment_mode: str = "http",
        proxy_protocol_enabled: bool = False,
        edge_token: Optional[str] = None,
        allow_http: bool = False,
        port_mappings: Optional[Iterable[dict[str, Any] | PortMapping]] = None,
        notes: Optional[str] = None,
    ) -> CDNEndpoint:
        name = (name or "").strip()
        domain = (domain or "").strip().lower()
        provider = (provider or "").strip()
        origin = (origin or "").strip()
        host = (host or "").strip()
        ssh_username = (ssh_username or "").strip()
        deployment_mode = (deployment_mode or "http").strip().lower()
        notes = (notes or "").strip() or None

        if len(name) < 3:
            raise ValueError("name_too_short")
        if not domain or "." not in domain:
            raise ValueError("domain_invalid")
        if not provider:
            raise ValueError("provider_required")
        if not origin:
            raise ValueError("origin_required")
        if not host:
            raise ValueError("host_required")
        if not ssh_username:
            raise ValueError("ssh_username_required")
        if deployment_mode not in {"http", "tcp"}:
            raise ValueError("deployment_mode_invalid")

        try:
            ssh_port = int(ssh_port)
            listen_port = int(listen_port)
            origin_port = int(origin_port)
        except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
            raise ValueError("port_invalid") from exc

        for port in (ssh_port, listen_port, origin_port):
            if port <= 0 or port > 65535:
                raise ValueError("port_invalid")

        existing = self.db.scalar(select(CDNEndpoint).where(CDNEndpoint.domain == domain))
        if existing:
            raise ValueError("domain_exists")

        settings = get_settings()
        raw_edge_token = edge_token.strip() if isinstance(edge_token, str) else None
        default_edge_token = settings.cdn_token.strip() if getattr(settings, "cdn_token", None) else None
        resolved_token = raw_edge_token or default_edge_token or secrets.token_urlsafe(24)
        if isinstance(resolved_token, str):
            resolved_token = resolved_token.strip()

        proxy_protocol_enabled = bool(proxy_protocol_enabled) if deployment_mode == "tcp" else False

        mapping_entries, effective_allow_http = self._build_port_mappings_payload(
            deployment_mode,
            listen_port,
            origin_port,
            port_mappings,
            allow_http_flag=bool(allow_http),
        )

        deploy_config = DeploymentConfig(
            origin_host=origin,
            origin_port=origin_port,
            listen_port=listen_port,
            edge_token=resolved_token or None,
            mode=deployment_mode,
            allow_http=effective_allow_http,
            proxy_protocol=proxy_protocol_enabled if deployment_mode == "tcp" else False,
        )

        if mapping_entries:
            deploy_config.port_mappings = mapping_entries

        try:
            deploy_config.normalize()
        except ValueError as exc:
            raise ValueError(str(exc)) from exc

        primary_listen_port = deploy_config.listen_port
        primary_origin_port = deploy_config.origin_port

        endpoint = CDNEndpoint(
            name=name,
            domain=domain,
            provider=provider,
            origin=origin,
            host=host,
            notes=notes,
            ssh_username=ssh_username,
            ssh_port=ssh_port,
            ssh_password_encrypted=encrypt_secret(ssh_password),
            ssh_private_key_encrypted=encrypt_secret(ssh_private_key),
            sudo_password_encrypted=encrypt_secret(sudo_password),
            listen_port=primary_listen_port,
            origin_port=primary_origin_port,
            deployment_mode=deployment_mode,
            edge_token=resolved_token or None,
            proxy_protocol_enabled=proxy_protocol_enabled,
        )
        endpoint.status = CDNEndpointStatus.PAUSED.value
        endpoint.last_deploy_status = CDNTaskStatus.PENDING.value

        self._apply_port_mappings(endpoint, deployment_mode, deploy_config.port_mappings)

        endpoint.listen_port = deploy_config.listen_port
        endpoint.origin_port = deploy_config.origin_port

        self.db.add(endpoint)
        self.db.commit()
        self.db.refresh(endpoint)

        return endpoint

    def update_endpoint(
        self,
        endpoint_id: int,
        *,
        name: str,
        domain: str,
        provider: str,
        origin: str,
        host: str,
        listen_port: int,
        origin_port: int,
        deployment_mode: str,
        proxy_protocol_enabled: bool = False,
        edge_token: Optional[str] = None,
        notes: Optional[str] = None,
        port_mappings: Optional[Iterable[dict[str, Any] | PortMapping]] = None,
    ) -> CDNEndpoint:
        endpoint = self.db.get(CDNEndpoint, endpoint_id)
        if not endpoint:
            raise ValueError("endpoint_not_found")

        name = (name or "").strip()
        domain = (domain or "").strip().lower()
        provider = (provider or "").strip()
        origin = (origin or "").strip()
        host = (host or "").strip()
        deployment_mode = (deployment_mode or "http").strip().lower()
        notes = (notes or "").strip() or None

        if len(name) < 3:
            raise ValueError("name_too_short")
        if not domain or "." not in domain:
            raise ValueError("domain_invalid")
        if not provider:
            raise ValueError("provider_required")
        if not origin:
            raise ValueError("origin_required")
        if not host:
            raise ValueError("host_required")
        if deployment_mode not in {"http", "tcp"}:
            raise ValueError("deployment_mode_invalid")

        try:
            ssh_port = int(endpoint.ssh_port or 22)
            listen_port = int(listen_port)
            origin_port = int(origin_port)
        except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
            raise ValueError("port_invalid") from exc

        for port in (ssh_port, listen_port, origin_port):
            if port <= 0 or port > 65535:
                raise ValueError("port_invalid")

        existing = self.db.scalar(select(CDNEndpoint).where(CDNEndpoint.domain == domain))
        if existing and existing.id != endpoint_id:
            raise ValueError("domain_exists")

        mapping_entries, effective_allow_http = self._build_port_mappings_payload(
            deployment_mode,
            listen_port,
            origin_port,
            port_mappings,
            allow_http_flag=False,
        )

        if edge_token is None:
            resolved_edge_token = endpoint.edge_token
        else:
            trimmed_token = edge_token.strip()
            resolved_edge_token = trimmed_token or None

        deploy_config = DeploymentConfig(
            origin_host=origin,
            origin_port=origin_port,
            listen_port=listen_port,
            edge_token=resolved_edge_token,
            mode=deployment_mode,
            allow_http=effective_allow_http,
            proxy_protocol=proxy_protocol_enabled if deployment_mode == "tcp" else False,
        )

        if mapping_entries:
            deploy_config.port_mappings = mapping_entries

        try:
            deploy_config.normalize()
        except ValueError as exc:
            raise ValueError(str(exc)) from exc

        endpoint.name = name
        endpoint.domain = domain
        endpoint.provider = provider
        endpoint.origin = origin
        endpoint.host = host
        endpoint.deployment_mode = deploy_config.mode
        if edge_token is not None:
            endpoint.edge_token = resolved_edge_token
        endpoint.proxy_protocol_enabled = deploy_config.proxy_protocol if deploy_config.mode == "tcp" else False
        endpoint.notes = notes

        self._apply_port_mappings(endpoint, deploy_config.mode, deploy_config.port_mappings)

        endpoint.listen_port = deploy_config.listen_port
        endpoint.origin_port = deploy_config.origin_port
        endpoint.updated_at = datetime.now(timezone.utc)

        self.db.flush()
        self._sync_origin_whitelist()
        self.db.commit()
        self.db.refresh(endpoint)
        return endpoint

    def set_endpoint_status(self, endpoint_id: int, status: CDNEndpointStatus) -> CDNEndpoint:
        endpoint = self.db.get(CDNEndpoint, endpoint_id)
        if not endpoint:
            raise ValueError("endpoint_not_found")
        endpoint.status = status.value
        endpoint.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(endpoint)
        return endpoint

    def delete_endpoint(self, endpoint_id: int) -> None:
        endpoint = self.db.get(CDNEndpoint, endpoint_id)
        if not endpoint:
            raise ValueError("endpoint_not_found")

        self.db.delete(endpoint)
        self.db.flush()
        self._sync_origin_whitelist()
        self.db.commit()

    def get_credentials(self, endpoint: CDNEndpoint) -> EndpointCredentials:
        ssh_password = decrypt_secret(endpoint.ssh_password_encrypted)
        sudo_password = decrypt_secret(endpoint.sudo_password_encrypted) or ssh_password
        return EndpointCredentials(
            host=endpoint.host,
            ssh_username=endpoint.ssh_username,
            ssh_port=endpoint.ssh_port,
            ssh_password=ssh_password,
            ssh_private_key=decrypt_secret(endpoint.ssh_private_key_encrypted),
            sudo_password=sudo_password,
        )

    def _resolve_endpoint_ips(self, endpoint: CDNEndpoint) -> list[str]:
        host = (endpoint.host or "").strip()
        if not host:
            return []

        try:
            ip_obj = ipaddress.ip_address(host)
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, None)
            except socket.gaierror:
                logger.warning("Unable to resolve CDN endpoint host", extra={"host": host})
                return []
            addresses = {info[4][0] for info in infos if info and info[4]}
            normalized = []
            for addr in addresses:
                try:
                    normalized.append(str(ipaddress.ip_address(addr)))
                except ValueError:
                    continue
            return sorted(set(normalized))
        else:
            return [str(ip_obj)]

    def _persist_whitelist_to_file(self, whitelist: list[str]) -> None:
        settings = get_settings()
        data_dir = settings.sqlite_path.parent
        data_dir.mkdir(parents=True, exist_ok=True)
        target = data_dir / "cdn_origin_whitelist.txt"
        if whitelist:
            content = "\n".join(whitelist) + "\n"
        else:
            content = ""
        target.write_text(content, encoding="utf-8")

    def _persist_whitelist_to_env(self, whitelist: list[str]) -> bool:
        if os.getenv("PYTEST_CURRENT_TEST"):
            return False
        env_path = Path(".env")
        if not env_path.exists():
            return False

        key = "VMP_CDN_IP_WHITELIST"
        new_line = f"{key}={','.join(whitelist)}"

        lines = env_path.read_text(encoding="utf-8").splitlines()
        updated = False
        for index, line in enumerate(lines):
            if line.startswith(f"{key}="):
                lines[index] = new_line
                updated = True
                break
        if not updated:
            lines.append(new_line)

        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return True

    def _sync_origin_whitelist(self) -> list[str]:
        endpoints = list(self.db.scalars(select(CDNEndpoint)).all())
        aggregated: set[str] = set()

        for endpoint in endpoints:
            resolved_ips = self._resolve_endpoint_ips(endpoint)
            endpoint.egress_ips = resolved_ips or None
            aggregated.update(resolved_ips)

        whitelist = sorted(aggregated)
        settings = get_settings()
        settings.cdn_ip_whitelist = whitelist

        try:
            self._persist_whitelist_to_file(whitelist)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to persist CDN whitelist file", exc_info=exc)

        try:
            self._persist_whitelist_to_env(whitelist)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to update .env whitelist", exc_info=exc)

        self.db.flush()
        return whitelist

    def _resolve_health_protocol(self, endpoint: CDNEndpoint, protocol: Optional[str]) -> str:
        if protocol:
            normalized = protocol.strip().lower()
        else:
            normalized = "tcp" if endpoint.deployment_mode == "tcp" else "https"

        if normalized not in {"http", "https", "tcp"}:
            raise ValueError("health_protocol_invalid")
        if endpoint.deployment_mode == "tcp" and normalized in {"http", "https"}:
            raise ValueError("health_protocol_unsupported")
        return normalized

    def _perform_health_probe(self, endpoint: CDNEndpoint, protocol: Optional[str]) -> HealthCheckResult:
        resolved = self._resolve_health_protocol(endpoint, protocol)
        if resolved == "tcp":
            return self.health_checker.check_tcp(endpoint.host, endpoint.listen_port)

        use_https = resolved != "http"
        host = endpoint.domain or endpoint.host
        return self.health_checker.check_http(host, endpoint.listen_port, use_https=use_https)

    def _create_config_snapshot(
        self,
        endpoint: CDNEndpoint,
        deploy_config: DeploymentConfig,
        firewall_ports: Iterable[int],
        *,
        whitelist: Optional[List[str]] = None,
    ) -> dict[str, object]:
        snapshot: dict[str, object] = {
            "origin_host": deploy_config.origin_host,
            "origin_port": deploy_config.origin_port,
            "listen_port": deploy_config.listen_port,
            "mode": deploy_config.mode,
            "allow_http": deploy_config.allow_http,
            "proxy_protocol": deploy_config.proxy_protocol,
            "edge_token": deploy_config.edge_token,
            "firewall_ports": list(firewall_ports),
            "extra_packages": list(deploy_config.extra_packages),
            "ssl_certificate": deploy_config.ssl_certificate,
            "ssl_certificate_key": deploy_config.ssl_certificate_key,
        }
        if deploy_config.port_mappings:
            snapshot["port_mappings"] = _serialize_port_mappings(deploy_config.port_mappings)
        if whitelist:
            snapshot["recommended_origin_ip_whitelist"] = list(whitelist)
        return snapshot

    def _config_from_snapshot(
        self,
        endpoint: CDNEndpoint,
        snapshot: Optional[dict[str, Any]],
    ) -> DeploymentConfig:
        data = snapshot or {}

        def _coerce_int(value: Any, default: int) -> int:
            try:
                return int(value)
            except (TypeError, ValueError):
                return default

        origin_host = str(data.get("origin_host") or endpoint.origin)
        origin_port = _coerce_int(data.get("origin_port"), endpoint.origin_port)
        listen_port = _coerce_int(data.get("listen_port"), endpoint.listen_port)
        mode = str(data.get("mode") or endpoint.deployment_mode).lower()

        allow_http_raw = data.get("allow_http")
        if allow_http_raw is None:
            allow_http_value = endpoint.deployment_mode == "http"
        else:
            allow_http_value = bool(allow_http_raw)

        proxy_protocol_raw = data.get("proxy_protocol")
        if proxy_protocol_raw is None:
            proxy_protocol_value = endpoint.proxy_protocol_enabled
        else:
            proxy_protocol_value = bool(proxy_protocol_raw)

        config = DeploymentConfig(
            origin_host=origin_host,
            origin_port=origin_port,
            listen_port=listen_port,
            edge_token=data.get("edge_token") or endpoint.edge_token,
            mode=mode,
            allow_http=allow_http_value,
            proxy_protocol=proxy_protocol_value,
        )

        extra_packages = data.get("extra_packages")
        if extra_packages:
            config.extra_packages = list(extra_packages)

        firewall_ports = data.get("firewall_ports")
        if firewall_ports:
            config.firewall_ports = list(firewall_ports)

        mapping_payloads = data.get("port_mappings")
        if mapping_payloads:
            config.port_mappings = [
                PortMapping(
                    listen_port=item.get("listen_port", listen_port),
                    origin_port=item.get("origin_port", origin_port),
                    allow_http=_parse_optional_bool(item.get("allow_http")),
                )
                for item in mapping_payloads
                if item is not None
            ]

        if data.get("ssl_certificate"):
            config.ssl_certificate = data.get("ssl_certificate")
        if data.get("ssl_certificate_key"):
            config.ssl_certificate_key = data.get("ssl_certificate_key")

        if config.mode != "http":
            config.allow_http = False
        if config.mode != "tcp":
            config.proxy_protocol = False

        return config

    def _apply_health_result(self, endpoint: CDNEndpoint, result: HealthCheckResult) -> CDNHealthCheck:
        record = CDNHealthCheck(
            endpoint=endpoint,
            status=result.status.value,
            protocol=result.protocol,
            latency_ms=result.latency_ms,
            status_code=result.status_code,
            message=result.message,
            checked_at=result.checked_at,
        )
        endpoint.health_status = result.status.value
        endpoint.health_checked_at = result.checked_at
        endpoint.health_latency_ms = result.latency_ms
        endpoint.health_error = None if result.status == CDNHealthStatus.HEALTHY else result.message
        endpoint.updated_at = result.checked_at
        self.db.add(record)
        return record

    def run_health_check(self, endpoint_id: int, *, protocol: Optional[str] = None) -> CDNHealthCheck:
        endpoint = self.db.get(CDNEndpoint, endpoint_id)
        if not endpoint:
            raise ValueError("endpoint_not_found")

        result = self._perform_health_probe(endpoint, protocol)
        record = self._apply_health_result(endpoint, result)

        self.db.commit()
        self.db.refresh(record)
        self.db.refresh(endpoint)
        return record

    def deploy_endpoint(
        self,
        endpoint_id: int,
        *,
        allow_http: Optional[bool] = None,
        use_proxy_protocol: Optional[bool] = None,
    ) -> CDNTask:
        endpoint = self.db.get(CDNEndpoint, endpoint_id)
        if not endpoint:
            raise ValueError("endpoint_not_found")

        if endpoint.deployment_mode != "tcp":
            endpoint.proxy_protocol_enabled = False

        if use_proxy_protocol is not None and endpoint.deployment_mode == "tcp":
            endpoint.proxy_protocol_enabled = use_proxy_protocol

        credentials = self.get_credentials(endpoint)
        target = DeploymentTarget(
            name=endpoint.name,
            host=credentials.host,
            username=credentials.ssh_username,
            port=credentials.ssh_port,
            password=credentials.ssh_password,
            private_key=credentials.ssh_private_key,
            sudo_password=credentials.sudo_password or credentials.ssh_password,
        )

        allow_http_override: Optional[bool] = None
        if endpoint.deployment_mode == "http":
            allow_http_override = allow_http

        deploy_config = self._build_deployment_config_from_endpoint(
            endpoint,
            allow_http_override=allow_http_override,
        )
        config_text = generate_nginx_config(deploy_config)

        task = CDNTask(
            endpoint=endpoint,
            task_type=CDNTaskType.DEPLOY.value,
            status=CDNTaskStatus.PENDING.value,
            payload=f"mode={endpoint.deployment_mode};listen={endpoint.listen_port};origin={endpoint.origin}:{endpoint.origin_port}",
        )
        self.db.add(task)
        self.db.flush()

        settings = get_settings()
        started_at = datetime.now(timezone.utc)
        firewall_ports_snapshot = sorted(set(deploy_config.firewall_ports))
        whitelist = list(settings.cdn_ip_whitelist) if settings.cdn_ip_whitelist else None
        config_snapshot = self._create_config_snapshot(
            endpoint,
            deploy_config,
            firewall_ports_snapshot,
            whitelist=whitelist,
        )

        stage_events: list[dict[str, str]] = []

        def _record_stage(stage: str, status: str, message: Optional[str] = None) -> None:
            entry = {
                "stage": stage,
                "status": status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            if message:
                entry["message"] = message
            stage_events.append(entry)
            deployment.stage_logs = list(stage_events)  # type: ignore[name-defined]

        deployment = CDNDeployment(
            endpoint=endpoint,
            task=task,
            status=CDNTaskStatus.PENDING.value,
            mode=endpoint.deployment_mode,
            allow_http=deploy_config.allow_http,
            proxy_protocol=endpoint.proxy_protocol_enabled,
            summary="部署初始化",
            config_snapshot=dict(config_snapshot),
            started_at=started_at,
            config_text=config_text,
            stage_logs=[],
        )
        self.db.add(deployment)
        self.db.flush()

        # Initialize stage timeline after deployment object is available
        stage_events.clear()
        _record_stage("queued", "completed")

        endpoint.updated_at = started_at
        endpoint.last_deploy_status = CDNTaskStatus.PENDING.value

        health_record: Optional[CDNHealthCheck] = None

        try:
            _record_stage("deployment", "started")
            result = self.deployer.deploy(target, deploy_config, precomputed_config=config_text)
            _record_stage("deployment", "completed")
        except DeploymentError as exc:
            _record_stage("deployment", "failed", str(exc))
            failure_time = datetime.now(timezone.utc)
            task.status = CDNTaskStatus.FAILED.value
            task.message = str(exc)
            task.completed_at = failure_time
            endpoint.status = CDNEndpointStatus.ERROR.value
            endpoint.last_deploy_status = task.status
            endpoint.last_deployed_at = failure_time
            endpoint.updated_at = failure_time
            endpoint.health_status = CDNHealthStatus.UNHEALTHY.value
            endpoint.health_checked_at = failure_time
            endpoint.health_latency_ms = None
            endpoint.health_error = str(exc)

            deployment.status = CDNTaskStatus.FAILED.value
            deployment.summary = str(exc)
            deployment.log = exc.log or None
            deployment.completed_at = failure_time
            if deployment.started_at:
                deployment.duration_ms = int((failure_time - deployment.started_at).total_seconds() * 1000)

            self._sync_origin_whitelist()
            latest_whitelist = list(settings.cdn_ip_whitelist) if settings.cdn_ip_whitelist else None
            if latest_whitelist:
                config_snapshot["recommended_origin_ip_whitelist"] = latest_whitelist
            else:
                config_snapshot.pop("recommended_origin_ip_whitelist", None)
            deployment.config_snapshot = dict(config_snapshot)

            self.db.commit()
            self.db.refresh(task)
            self.db.refresh(deployment)
            raise

        completion = result.completed_at
        task.status = CDNTaskStatus.COMPLETED.value
        task.message = result.summary
        task.completed_at = completion

        deployment.status = CDNTaskStatus.COMPLETED.value
        deployment.summary = result.summary
        deployment.log = result.log
        deployment.completed_at = completion
        deployment.duration_ms = result.duration_ms

        _record_stage("health_check", "started")
        health_result = self._perform_health_probe(endpoint, None)
        health_record = self._apply_health_result(endpoint, health_result)
        _record_stage("health_check", "completed", health_result.status.value)

        endpoint.status = CDNEndpointStatus.ACTIVE.value
        endpoint.last_deployed_at = completion
        endpoint.last_deploy_status = task.status
        endpoint.updated_at = max(completion, health_result.checked_at)

        _record_stage("sync_whitelist", "started")
        whitelist = self._sync_origin_whitelist()
        _record_stage("sync_whitelist", "completed")
        if whitelist:
            config_snapshot["recommended_origin_ip_whitelist"] = whitelist
        else:
            config_snapshot.pop("recommended_origin_ip_whitelist", None)
        deployment.config_snapshot = dict(config_snapshot)

        self.db.commit()
        self.db.refresh(task)
        self.db.refresh(deployment)
        if health_record is not None:
            self.db.refresh(health_record)
        return task

    def rollback_deployment(
        self,
        endpoint_id: int,
        deployment_id: int,
        *,
        allow_http: Optional[bool] = None,
        initiated_by: Optional[str] = None,
        initiated_by_id: Optional[int] = None,
    ) -> CDNTask:
        endpoint = self.db.get(CDNEndpoint, endpoint_id)
        if not endpoint:
            raise ValueError("endpoint_not_found")

        source_deployment = self.db.get(CDNDeployment, deployment_id)
        if not source_deployment or source_deployment.endpoint_id != endpoint_id:
            raise ValueError("deployment_not_found")

        deploy_config = self._config_from_snapshot(endpoint, source_deployment.config_snapshot)
        if allow_http is not None and deploy_config.mode == "http":
            deploy_config.allow_http = allow_http

        config_text = source_deployment.config_text or generate_nginx_config(deploy_config)

        credentials = self.get_credentials(endpoint)
        target = DeploymentTarget(
            name=endpoint.name,
            host=credentials.host,
            username=credentials.ssh_username,
            port=credentials.ssh_port,
            password=credentials.ssh_password,
            private_key=credentials.ssh_private_key,
            sudo_password=credentials.sudo_password or credentials.ssh_password,
        )

        task = CDNTask(
            endpoint=endpoint,
            task_type=CDNTaskType.DEPLOY.value,
            status=CDNTaskStatus.PENDING.value,
            payload=f"rollback={deployment_id}",
        )
        self.db.add(task)
        self.db.flush()

        settings = get_settings()
        started_at = datetime.now(timezone.utc)
        firewall_ports_snapshot = sorted(set(deploy_config.firewall_ports))
        whitelist = list(settings.cdn_ip_whitelist) if settings.cdn_ip_whitelist else None
        config_snapshot = self._create_config_snapshot(
            endpoint,
            deploy_config,
            firewall_ports_snapshot,
            whitelist=whitelist,
        )

        stage_events: list[dict[str, str]] = []

        def _record_stage(stage: str, status: str, message: Optional[str] = None) -> None:
            entry = {
                "stage": stage,
                "status": status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            if message:
                entry["message"] = message
            stage_events.append(entry)
            deployment.stage_logs = list(stage_events)  # type: ignore[name-defined]

        deployment = CDNDeployment(
            endpoint=endpoint,
            task=task,
            status=CDNTaskStatus.PENDING.value,
            mode=deploy_config.mode,
            allow_http=deploy_config.allow_http,
            proxy_protocol=deploy_config.proxy_protocol,
            summary=f"回滚到部署 {deployment_id}",
            config_snapshot=dict(config_snapshot),
            started_at=started_at,
            config_text=config_text,
            rolled_back_from=source_deployment,
            stage_logs=[],
            initiated_by=initiated_by,
            initiated_by_id=initiated_by_id,
        )
        self.db.add(deployment)
        self.db.flush()

        stage_events.clear()
        _record_stage("queued", "completed")

        endpoint.updated_at = started_at
        endpoint.last_deploy_status = CDNTaskStatus.PENDING.value

        health_record: Optional[CDNHealthCheck] = None

        try:
            _record_stage("deployment", "started")
            result = self.deployer.deploy(target, deploy_config, precomputed_config=config_text)
            _record_stage("deployment", "completed")
        except DeploymentError as exc:
            _record_stage("deployment", "failed", str(exc))
            failure_time = datetime.now(timezone.utc)
            task.status = CDNTaskStatus.FAILED.value
            task.message = str(exc)
            task.completed_at = failure_time
            endpoint.status = CDNEndpointStatus.ERROR.value
            endpoint.last_deploy_status = task.status
            endpoint.last_deployed_at = failure_time
            endpoint.updated_at = failure_time
            endpoint.health_status = CDNHealthStatus.UNHEALTHY.value
            endpoint.health_checked_at = failure_time
            endpoint.health_latency_ms = None
            endpoint.health_error = str(exc)

            deployment.status = CDNTaskStatus.FAILED.value
            deployment.summary = str(exc)
            deployment.log = exc.log or None
            deployment.completed_at = failure_time
            if deployment.started_at:
                deployment.duration_ms = int((failure_time - deployment.started_at).total_seconds() * 1000)

            self._sync_origin_whitelist()
            latest_whitelist = list(settings.cdn_ip_whitelist) if settings.cdn_ip_whitelist else None
            if latest_whitelist:
                config_snapshot["recommended_origin_ip_whitelist"] = latest_whitelist
            else:
                config_snapshot.pop("recommended_origin_ip_whitelist", None)
            deployment.config_snapshot = dict(config_snapshot)

            self.db.commit()
            self.db.refresh(task)
            self.db.refresh(deployment)
            raise

        completion = result.completed_at
        task.status = CDNTaskStatus.COMPLETED.value
        task.message = result.summary
        task.completed_at = completion

        deployment.status = CDNTaskStatus.COMPLETED.value
        deployment.summary = result.summary
        deployment.log = result.log
        deployment.completed_at = completion
        deployment.duration_ms = result.duration_ms

        _record_stage("health_check", "started")
        health_result = self._perform_health_probe(endpoint, None)
        health_record = self._apply_health_result(endpoint, health_result)
        _record_stage("health_check", "completed", health_result.status.value)

        endpoint.status = CDNEndpointStatus.ACTIVE.value
        endpoint.origin = deploy_config.origin_host
        self._apply_port_mappings(endpoint, deploy_config.mode, deploy_config.port_mappings)
        endpoint.listen_port = int(deploy_config.listen_port)
        endpoint.origin_port = int(deploy_config.origin_port)
        endpoint.deployment_mode = deploy_config.mode
        endpoint.edge_token = deploy_config.edge_token
        endpoint.proxy_protocol_enabled = deploy_config.proxy_protocol if deploy_config.mode == "tcp" else False
        endpoint.last_deployed_at = completion
        endpoint.last_deploy_status = task.status
        endpoint.updated_at = max(completion, health_result.checked_at)

        _record_stage("sync_whitelist", "started")
        whitelist_after = self._sync_origin_whitelist()
        _record_stage("sync_whitelist", "completed")
        if whitelist_after:
            config_snapshot["recommended_origin_ip_whitelist"] = whitelist_after
        else:
            config_snapshot.pop("recommended_origin_ip_whitelist", None)
        deployment.config_snapshot = dict(config_snapshot)

        self.db.commit()
        self.db.refresh(task)
        self.db.refresh(deployment)
        if health_record is not None:
            self.db.refresh(health_record)
        return task

    # Tasks ----------------------------------------------------------------------
    def list_recent_tasks(self, limit: int = 20) -> List[CDNTask]:
        stmt = (
            select(CDNTask)
            .options(selectinload(CDNTask.endpoint))
            .order_by(CDNTask.created_at.desc())
            .limit(max(1, min(limit, 100)))
        )
        return list(self.db.scalars(stmt).all())

    def create_task(
        self,
        *,
        endpoint_id: int,
        task_type: CDNTaskType,
        payload: Optional[str] = None,
    ) -> CDNTask:
        if task_type == CDNTaskType.DEPLOY:
            raise ValueError("unsupported_manual_deploy")

        endpoint = self.db.get(CDNEndpoint, endpoint_id)
        if not endpoint:
            raise ValueError("endpoint_not_found")

        task = CDNTask(
            endpoint=endpoint,
            task_type=task_type.value,
            payload=payload.strip() if payload else None,
        )
        self.db.add(task)
        self.db.flush()

        now = datetime.now(timezone.utc)
        task.status = CDNTaskStatus.COMPLETED.value
        task.message = "Task simulated as completed"
        task.completed_at = now
        endpoint.updated_at = now

        self.db.commit()
        self.db.refresh(task)
        return task

    def mark_task_failed(self, task_id: int, message: str) -> CDNTask:
        task = self.db.get(CDNTask, task_id)
        if not task:
            raise ValueError("task_not_found")
        task.status = CDNTaskStatus.FAILED.value
        task.message = message
        task.completed_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(task)
        return task

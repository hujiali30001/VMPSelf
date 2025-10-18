from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import logging
import os
import socket
from pathlib import Path
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.crypto import decrypt_secret, encrypt_secret
from app.core.settings import get_settings
from app.db import (
    CDNDeployment,
    CDNEndpoint,
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
)
from app.services.cdn.health import CDNHealthChecker, HealthCheckResult


logger = logging.getLogger(__name__)


@dataclass
class EndpointCredentials:
    host: str
    ssh_username: str
    ssh_port: int
    ssh_password: Optional[str]
    ssh_private_key: Optional[str]


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

    # Endpoints -----------------------------------------------------------------
    def list_endpoints(self) -> List[CDNEndpoint]:
        stmt = (
            select(CDNEndpoint)
            .options(
                selectinload(CDNEndpoint.tasks),
                selectinload(CDNEndpoint.deployments),
                selectinload(CDNEndpoint.health_checks),
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
        ssh_port: int = 22,
        listen_port: int = 443,
        origin_port: int = 443,
        deployment_mode: str = "http",
        proxy_protocol_enabled: bool = False,
        edge_token: Optional[str] = None,
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
        resolved_token = (edge_token or settings.cdn_token or secrets.token_urlsafe(24)).strip()

        proxy_protocol_enabled = bool(proxy_protocol_enabled) if deployment_mode == "tcp" else False

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
            listen_port=listen_port,
            origin_port=origin_port,
            deployment_mode=deployment_mode,
            edge_token=resolved_token or None,
            proxy_protocol_enabled=proxy_protocol_enabled,
        )
        endpoint.status = CDNEndpointStatus.PAUSED.value
        endpoint.last_deploy_status = CDNTaskStatus.PENDING.value

        self.db.add(endpoint)
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

    def get_credentials(self, endpoint: CDNEndpoint) -> EndpointCredentials:
        return EndpointCredentials(
            host=endpoint.host,
            ssh_username=endpoint.ssh_username,
            ssh_port=endpoint.ssh_port,
            ssh_password=decrypt_secret(endpoint.ssh_password_encrypted),
            ssh_private_key=decrypt_secret(endpoint.ssh_private_key_encrypted),
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
        allow_http: bool = False,
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
        )

        deploy_config = DeploymentConfig(
            origin_host=endpoint.origin,
            origin_port=endpoint.origin_port,
            listen_port=endpoint.listen_port,
            edge_token=endpoint.edge_token,
            mode=endpoint.deployment_mode,
            allow_http=allow_http if endpoint.deployment_mode == "http" else False,
            proxy_protocol=endpoint.proxy_protocol_enabled if endpoint.deployment_mode == "tcp" else False,
        )

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
        firewall_ports_snapshot = sorted({*deploy_config.firewall_ports, deploy_config.listen_port})
        config_snapshot: dict[str, object] = {
            "origin_host": endpoint.origin,
            "origin_port": endpoint.origin_port,
            "listen_port": endpoint.listen_port,
            "mode": endpoint.deployment_mode,
            "allow_http": deploy_config.allow_http,
            "proxy_protocol": endpoint.proxy_protocol_enabled,
            "edge_token_present": bool(endpoint.edge_token),
            "firewall_ports": firewall_ports_snapshot,
        }
        if settings.cdn_ip_whitelist:
            config_snapshot["recommended_origin_ip_whitelist"] = list(settings.cdn_ip_whitelist)

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
        )
        self.db.add(deployment)
        self.db.flush()

        endpoint.updated_at = started_at
        endpoint.last_deploy_status = CDNTaskStatus.PENDING.value

        health_record: Optional[CDNHealthCheck] = None

        try:
            result = self.deployer.deploy(target, deploy_config)
        except DeploymentError as exc:
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
            config_snapshot["recommended_origin_ip_whitelist"] = settings.cdn_ip_whitelist
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

        health_result = self._perform_health_probe(endpoint, None)
        health_record = self._apply_health_result(endpoint, health_result)

        endpoint.status = CDNEndpointStatus.ACTIVE.value
        endpoint.last_deployed_at = completion
        endpoint.last_deploy_status = task.status
        endpoint.updated_at = max(completion, health_result.checked_at)

        whitelist = self._sync_origin_whitelist()
        config_snapshot["recommended_origin_ip_whitelist"] = whitelist
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

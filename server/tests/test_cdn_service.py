from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.db import CDNEndpointStatus, CDNHealthStatus, CDNTaskStatus, CDNTaskType
from app.db.session import SessionLocal
from app.services.cdn import (
    CDNService,
    DeploymentConfig,
    DeploymentError,
    DeploymentResult,
    DeploymentTarget,
    HealthCheckResult,
)


class _FakeDeployer:
    def __init__(self, *, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.calls: list[tuple[DeploymentTarget, DeploymentConfig]] = []

    def deploy(self, target: DeploymentTarget, config: DeploymentConfig) -> DeploymentResult:  # type: ignore[override]
        self.calls.append((target, config))
        if self.should_fail:
            raise DeploymentError("boom", log="failed during fake deploy")

        started = datetime.now(timezone.utc)
        completed = started + timedelta(milliseconds=120)
        return DeploymentResult(
            started_at=started,
            completed_at=completed,
            log="fake deploy step 1\nfake deploy step 2",
            summary="模拟部署成功",
        )


class _FakeHealthChecker:
    def __init__(
        self,
        *,
        status: CDNHealthStatus = CDNHealthStatus.HEALTHY,
        http_message: str = "OK",
        tcp_message: str = "TCP OK",
    ) -> None:
        self.status = status
        self.http_message = http_message
        self.tcp_message = tcp_message
        self.http_calls: list[tuple[str, int, bool]] = []
        self.tcp_calls: list[tuple[str, int]] = []

    def check_http(self, host: str, port: int, *, use_https: bool = True, path: str = "/") -> HealthCheckResult:  # type: ignore[override]
        self.http_calls.append((host, port, use_https))
        return HealthCheckResult(
            status=self.status,
            protocol="https" if use_https else "http",
            latency_ms=42,
            status_code=200,
            message=self.http_message,
            checked_at=datetime.now(timezone.utc),
        )

    def check_tcp(self, host: str, port: int) -> HealthCheckResult:  # type: ignore[override]
        self.tcp_calls.append((host, port))
        return HealthCheckResult(
            status=self.status,
            protocol="tcp",
            latency_ms=15,
            status_code=None,
            message=self.tcp_message,
            checked_at=datetime.now(timezone.utc),
        )


def _create_endpoint(service: CDNService, **overrides) -> int:
    payload = {
        "name": "Edge-1",
        "domain": "cdn.example.com",
        "provider": "ExampleCDN",
        "origin": "origin.internal",
        "host": "203.0.113.10",
        "ssh_username": "root",
        "ssh_password": "password123",
        "ssh_port": 22,
        "listen_port": 443,
        "origin_port": 8443,
        "deployment_mode": "http",
        "edge_token": "edge-token",
    }
    payload.update(overrides)
    endpoint = service.create_endpoint(**payload)
    return endpoint.id


def test_create_endpoint_encrypts_credentials():
    fake = _FakeDeployer()
    fake_health = _FakeHealthChecker()
    with SessionLocal() as session:
        service = CDNService(session, deployer=fake, health_checker=fake_health)
        endpoint_id = _create_endpoint(service)
        endpoint = service.get_endpoint(endpoint_id)
        assert endpoint is not None
        assert endpoint.ssh_password_encrypted is not None
        assert "password123" not in endpoint.ssh_password_encrypted

        creds = service.get_credentials(endpoint)
        assert creds.ssh_password == "password123"
        assert creds.ssh_username == "root"
        assert creds.host == "203.0.113.10"


def test_deploy_endpoint_success_updates_status_and_creates_task():
    fake = _FakeDeployer()
    fake_health = _FakeHealthChecker()
    with SessionLocal() as session:
        service = CDNService(session, deployer=fake, health_checker=fake_health)
        endpoint_id = _create_endpoint(service)

        task = service.deploy_endpoint(endpoint_id, allow_http=True)
        assert task.status == CDNTaskStatus.COMPLETED.value
        assert task.task_type == CDNTaskType.DEPLOY.value
        assert task.message == "模拟部署成功"

        refreshed = service.get_endpoint(endpoint_id)
        assert refreshed is not None
        assert refreshed.status == CDNEndpointStatus.ACTIVE.value
        assert refreshed.last_deploy_status == CDNTaskStatus.COMPLETED.value
        assert refreshed.last_deployed_at is not None
        assert refreshed.updated_at is not None
        assert refreshed.listen_port == 443
        assert refreshed.health_status == CDNHealthStatus.HEALTHY.value
        assert refreshed.health_latency_ms == 42
        assert refreshed.health_error is None

        assert refreshed.deployments
        latest_deployment = refreshed.deployments[0]
        assert latest_deployment.status == CDNTaskStatus.COMPLETED.value
        assert latest_deployment.summary == "模拟部署成功"
        assert "fake deploy step" in (latest_deployment.log or "")
        assert latest_deployment.allow_http is True

        assert refreshed.health_checks
        latest_health = refreshed.health_checks[0]
        assert latest_health.protocol == "https"
        assert latest_health.status == CDNHealthStatus.HEALTHY.value
        assert latest_health.latency_ms == 42

        assert len(fake.calls) == 1
        target, config = fake.calls[0]
        assert target.host == "203.0.113.10"
        assert target.username == "root"
        assert config.mode == "http"
        assert config.allow_http is True
        assert config.listen_port == 443
        assert config.origin_port == 8443

        assert fake_health.http_calls
        host, port, use_https = fake_health.http_calls[0]
        assert host == "cdn.example.com"
        assert port == 443
        assert use_https is True

        assert isinstance(task.completed_at, datetime)
        if task.completed_at:
            assert task.completed_at.tzinfo is None or task.completed_at.tzinfo == timezone.utc


def test_deploy_endpoint_failure_marks_endpoint_error():
    fake = _FakeDeployer(should_fail=True)
    fake_health = _FakeHealthChecker()
    with SessionLocal() as session:
        service = CDNService(session, deployer=fake, health_checker=fake_health)
        endpoint_id = _create_endpoint(service)

        with pytest.raises(DeploymentError):
            service.deploy_endpoint(endpoint_id)

        refreshed = service.get_endpoint(endpoint_id)
        assert refreshed is not None
        assert refreshed.status == CDNEndpointStatus.ERROR.value
        assert refreshed.last_deploy_status == CDNTaskStatus.FAILED.value
        assert refreshed.last_deployed_at is not None
        assert refreshed.health_status == CDNHealthStatus.UNHEALTHY.value
        assert refreshed.health_error == "boom"
        assert not refreshed.health_checks

        assert refreshed.deployments
        failed_deployment = refreshed.deployments[0]
        assert failed_deployment.status == CDNTaskStatus.FAILED.value
        assert failed_deployment.summary == "boom"
        assert "failed" in (failed_deployment.log or "")

        tasks = service.list_recent_tasks(limit=5)
        assert tasks
        assert tasks[0].status == CDNTaskStatus.FAILED.value


def test_run_health_check_records_entry():
    fake = _FakeDeployer()
    fake_health = _FakeHealthChecker(status=CDNHealthStatus.DEGRADED, http_message="HTTP 502")
    with SessionLocal() as session:
        service = CDNService(session, deployer=fake, health_checker=fake_health)
        endpoint_id = _create_endpoint(service)

        record = service.run_health_check(endpoint_id, protocol="https")
        assert record.status == CDNHealthStatus.DEGRADED.value
        assert record.message == "HTTP 502"

        endpoint = service.get_endpoint(endpoint_id)
        assert endpoint.health_status == CDNHealthStatus.DEGRADED.value
        assert endpoint.health_error == "HTTP 502"
        assert fake_health.http_calls


def test_run_health_check_tcp_enforces_protocol():
    fake = _FakeDeployer()
    fake_health = _FakeHealthChecker()
    with SessionLocal() as session:
        service = CDNService(session, deployer=fake, health_checker=fake_health)
        endpoint_id = _create_endpoint(service, deployment_mode="tcp", listen_port=8443)

        record = service.run_health_check(endpoint_id)
        assert record.protocol == "tcp"
        assert fake_health.tcp_calls == [("203.0.113.10", 8443)]

        with pytest.raises(ValueError):
            service.run_health_check(endpoint_id, protocol="http")


def test_manual_deploy_task_not_allowed():
    fake = _FakeDeployer()
    fake_health = _FakeHealthChecker()
    with SessionLocal() as session:
        service = CDNService(session, deployer=fake, health_checker=fake_health)
        endpoint_id = _create_endpoint(service)

        with pytest.raises(ValueError) as exc:
            service.create_task(endpoint_id=endpoint_id, task_type=CDNTaskType.DEPLOY)
        assert str(exc.value) == "unsupported_manual_deploy"

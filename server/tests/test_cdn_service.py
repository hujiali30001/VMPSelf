from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest

from app.db import CDNEndpointStatus, CDNHealthStatus, CDNTaskStatus, CDNTaskType, models
from app.db.session import SessionLocal
from app.core.settings import get_settings
from app.services.cdn import (
    CDNHealthMonitor,
    CDNMonitorConfigService,
    CDNService,
    DeploymentConfig,
    DeploymentError,
    DeploymentResult,
    DeploymentTarget,
    HealthCheckResult,
    should_enable_monitor,
)


class _FakeDeployer:
    def __init__(self, *, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.calls: list[tuple[DeploymentTarget, DeploymentConfig, Optional[str]]] = []

    def deploy(
        self,
        target: DeploymentTarget,
        config: DeploymentConfig,
        *,
        precomputed_config: Optional[str] = None,
    ) -> DeploymentResult:  # type: ignore[override]
        self.calls.append((target, config, precomputed_config))
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
        "proxy_protocol_enabled": False,
        "sudo_password": None,
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
    assert creds.sudo_password == "password123"


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
        assert refreshed.egress_ips == ["203.0.113.10"]

        assert refreshed.deployments
        latest_deployment = refreshed.deployments[0]
        assert latest_deployment.status == CDNTaskStatus.COMPLETED.value
        assert latest_deployment.summary == "模拟部署成功"
        assert "fake deploy step" in (latest_deployment.log or "")
        assert latest_deployment.allow_http is True
        assert latest_deployment.config_snapshot.get("recommended_origin_ip_whitelist") == ["203.0.113.10"]
        assert latest_deployment.config_snapshot.get("firewall_ports") == [80, 443, 8000]
        assert latest_deployment.config_text is not None
        assert latest_deployment.stage_logs
        stage_sequence = [(entry.get("stage"), entry.get("status")) for entry in latest_deployment.stage_logs]
        assert stage_sequence[0] == ("queued", "completed")
        assert ("deployment", "started") in stage_sequence
        assert ("deployment", "completed") in stage_sequence
        assert ("health_check", "started") in stage_sequence
        assert any(stage == "health_check" and status == "completed" for stage, status in stage_sequence)
        assert ("sync_whitelist", "started") in stage_sequence
        assert ("sync_whitelist", "completed") in stage_sequence

        assert refreshed.health_checks
        latest_health = refreshed.health_checks[0]
        assert latest_health.protocol == "https"
        assert latest_health.status == CDNHealthStatus.HEALTHY.value
        assert latest_health.latency_ms == 42

        assert len(fake.calls) == 1
        target, config, config_text = fake.calls[0]
        assert target.host == "203.0.113.10"
        assert target.username == "root"
        assert target.password == "password123"
        assert target.sudo_password == "password123"
        assert config.mode == "http"
        assert config.allow_http is True
        assert config.proxy_protocol is False
        assert config.listen_port == 443
        assert config.origin_port == 8443
        assert config_text is not None
        assert latest_deployment.config_text == config_text

        assert fake_health.http_calls
        host, port, use_https = fake_health.http_calls[0]
        assert host == "cdn.example.com"
        assert port == 443
        assert use_https is True

        assert isinstance(task.completed_at, datetime)
        if task.completed_at:
            assert task.completed_at.tzinfo is None or task.completed_at.tzinfo == timezone.utc


def test_deploy_endpoint_supports_distinct_sudo_password():
    fake = _FakeDeployer()
    fake_health = _FakeHealthChecker()
    with SessionLocal() as session:
        service = CDNService(session, deployer=fake, health_checker=fake_health)
        endpoint_id = _create_endpoint(
            service,
            ssh_password="ssh-secret",
            sudo_password="sudo-secret",
        )

        service.deploy_endpoint(endpoint_id)
        assert fake.calls
        target, _, config_text = fake.calls[-1]
        assert target.password == "ssh-secret"
        assert target.sudo_password == "sudo-secret"
        assert config_text is not None


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
        assert refreshed.egress_ips == ["203.0.113.10"]

        assert refreshed.deployments
        failed_deployment = refreshed.deployments[0]
        assert failed_deployment.status == CDNTaskStatus.FAILED.value
        assert failed_deployment.summary == "boom"
        assert "failed" in (failed_deployment.log or "")
        assert failed_deployment.stage_logs
        failure_sequence = [(entry.get("stage"), entry.get("status")) for entry in failed_deployment.stage_logs]
        assert failure_sequence[0] == ("queued", "completed")
        assert failure_sequence[-1] == ("deployment", "failed")
        assert any(entry.get("message") == "boom" for entry in failed_deployment.stage_logs)

        tasks = service.list_recent_tasks(limit=5)
        assert tasks
        assert tasks[0].status == CDNTaskStatus.FAILED.value


def test_rollback_deployment_reuses_snapshot_and_stage_logs():
    fake = _FakeDeployer()
    fake_health = _FakeHealthChecker()
    with SessionLocal() as session:
        service = CDNService(session, deployer=fake, health_checker=fake_health)
        endpoint_id = _create_endpoint(service)

        service.deploy_endpoint(endpoint_id, allow_http=True)
        refreshed = service.get_endpoint(endpoint_id)
        assert refreshed is not None
        assert refreshed.deployments
        first_deployment = refreshed.deployments[0]
        first_deployment_id = first_deployment.id
        assert first_deployment_id is not None
        first_config_text = first_deployment.config_text
        assert first_config_text

        endpoint = service.get_endpoint(endpoint_id)
        assert endpoint is not None
        endpoint.origin = "modified.internal"
        endpoint.origin_port = 9443
        endpoint.listen_port = 5443
        session.commit()

        service.deploy_endpoint(endpoint_id, allow_http=False)
        assert len(fake.calls) == 2

        rollback_task = service.rollback_deployment(
            endpoint_id,
            first_deployment_id,
            allow_http=True,
            initiated_by="ops-bot",
            initiated_by_id=42,
        )

        assert rollback_task.status == CDNTaskStatus.COMPLETED.value
        assert len(fake.calls) == 3
        target, config, config_text = fake.calls[-1]
        assert target.host == "203.0.113.10"
        assert config.origin_host == "origin.internal"
        assert config.origin_port == 8443
        assert config.listen_port == 443
        assert config.allow_http is True
        assert config_text == first_config_text

        session.expire_all()
        refreshed = service.get_endpoint(endpoint_id)
        assert refreshed is not None
        assert refreshed.origin == "origin.internal"
        assert refreshed.origin_port == 8443
        assert refreshed.listen_port == 443

        latest_deployment = refreshed.deployments[0]
        assert latest_deployment.status == CDNTaskStatus.COMPLETED.value
        assert latest_deployment.rolled_back_from_id == first_deployment_id
        assert latest_deployment.rolled_back_from is not None
        assert latest_deployment.summary == "模拟部署成功"
        assert latest_deployment.initiated_by == "ops-bot"
        assert latest_deployment.initiated_by_id == 42
        assert latest_deployment.config_text == first_config_text
        assert latest_deployment.config_snapshot
        assert latest_deployment.config_snapshot.get("origin_host") == "origin.internal"
        assert latest_deployment.config_snapshot.get("listen_port") == 443
        assert latest_deployment.stage_logs
        assert any(
            entry.get("stage") == "deployment" and entry.get("status") == "completed"
            for entry in latest_deployment.stage_logs
        )
        assert any(
            entry.get("stage") == "health_check" and entry.get("status") == "completed"
            for entry in latest_deployment.stage_logs
        )

        session.refresh(first_deployment)
        assert first_deployment.rollbacks
        assert any(child.id == latest_deployment.id for child in first_deployment.rollbacks)


def test_tcp_deploy_respects_proxy_protocol_toggle():
    fake = _FakeDeployer()
    fake_health = _FakeHealthChecker()
    with SessionLocal() as session:
        service = CDNService(session, deployer=fake, health_checker=fake_health)
        endpoint_id = _create_endpoint(
            service,
            deployment_mode="tcp",
            listen_port=7001,
            origin_port=7002,
        )

        # Enable proxy protocol explicitly
        service.deploy_endpoint(endpoint_id, use_proxy_protocol=True)
        refreshed = service.get_endpoint(endpoint_id)
        assert refreshed is not None
        assert refreshed.proxy_protocol_enabled is True
        assert refreshed.egress_ips == ["203.0.113.10"]
        target, config, config_text = fake.calls[-1]
        assert config.mode == "tcp"
        assert config.proxy_protocol is True
        assert config.allow_http is False
        assert target.sudo_password == "password123"
        assert config_text is not None

        latest_deployment = refreshed.deployments[0]
        assert latest_deployment.proxy_protocol is True

        # Subsequent deploy without override keeps previous preference
        service.deploy_endpoint(endpoint_id)
        refreshed = service.get_endpoint(endpoint_id)
        assert refreshed.proxy_protocol_enabled is True
        target, config, config_text = fake.calls[-1]
        assert config.proxy_protocol is True
        assert target.sudo_password == "password123"
        assert config_text is not None

        # Disable proxy protocol
        service.deploy_endpoint(endpoint_id, use_proxy_protocol=False)
        refreshed = service.get_endpoint(endpoint_id)
        assert refreshed.proxy_protocol_enabled is False
        assert refreshed.egress_ips == ["203.0.113.10"]
        target, config, config_text = fake.calls[-1]
        assert config.proxy_protocol is False
        assert target.sudo_password == "password123"
        assert refreshed.deployments[0].proxy_protocol is False
        assert config_text is not None


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


def test_delete_endpoint_removes_records_and_updates_whitelist():
    fake = _FakeDeployer()
    fake_health = _FakeHealthChecker()
    settings = get_settings()
    settings.cdn_ip_whitelist = []

    with SessionLocal() as session:
        service = CDNService(session, deployer=fake, health_checker=fake_health)
        first_id = _create_endpoint(
            service,
            name="Edge-A",
            domain="edge-a.example.com",
            host="198.51.100.10",
        )
        second_id = _create_endpoint(
            service,
            name="Edge-B",
            domain="edge-b.example.com",
            host="198.51.100.11",
        )

        service.create_task(endpoint_id=first_id, task_type=CDNTaskType.PURGE, payload="/static")
        service.create_task(endpoint_id=second_id, task_type=CDNTaskType.PURGE, payload="/media")

        service.delete_endpoint(first_id)

        assert service.get_endpoint(first_id) is None
        session.expire_all()
        remaining = service.get_endpoint(second_id)
        assert remaining is not None
        assert remaining.domain == "edge-b.example.com"
        assert remaining.egress_ips == ["198.51.100.11"]

        remaining_tasks = session.query(models.CDNTask).filter_by(endpoint_id=first_id).count()
        assert remaining_tasks == 0

    assert get_settings().cdn_ip_whitelist == ["198.51.100.11"]


def test_health_monitor_logs_alert(monkeypatch):
    with SessionLocal() as session:
        service = CDNService(session)
        endpoint_id = _create_endpoint(service)
        endpoint = service.get_endpoint(endpoint_id)
        assert endpoint is not None
        endpoint.status = CDNEndpointStatus.ACTIVE.value
        endpoint.health_status = CDNHealthStatus.HEALTHY.value
        session.commit()

    def fake_probe(self, endpoint, protocol):
        return HealthCheckResult(
            status=CDNHealthStatus.UNHEALTHY,
            protocol="https",
            latency_ms=180,
            status_code=502,
            message="自动巡检失败",
            checked_at=datetime.now(timezone.utc),
        )

    monkeypatch.setattr(CDNService, "_perform_health_probe", fake_probe)

    monitor = CDNHealthMonitor(SessionLocal, interval_seconds=60)
    monitor._execute_cycle()

    with SessionLocal() as session:
        endpoint = session.get(models.CDNEndpoint, endpoint_id)
        assert endpoint is not None
        assert endpoint.health_status == CDNHealthStatus.UNHEALTHY.value
        logs = (
            session.query(models.AuditLog)
            .filter(models.AuditLog.action == "health_alert")
            .order_by(models.AuditLog.created_at.asc())
            .all()
        )
        assert logs, "expected health alert audit log"
        assert logs[0].target_id == str(endpoint_id)
        payload = logs[0].payload or {}
        assert payload.get("status") == CDNHealthStatus.UNHEALTHY.value
        assert payload.get("latency_ms") == 180


def test_health_monitor_logs_recovery(monkeypatch):
    with SessionLocal() as session:
        service = CDNService(session)
        endpoint_id = _create_endpoint(service)
        endpoint = service.get_endpoint(endpoint_id)
        assert endpoint is not None
        endpoint.status = CDNEndpointStatus.ACTIVE.value
        endpoint.health_status = CDNHealthStatus.UNHEALTHY.value
        session.commit()

    def fake_probe(self, endpoint, protocol):
        return HealthCheckResult(
            status=CDNHealthStatus.HEALTHY,
            protocol="https",
            latency_ms=55,
            status_code=200,
            message="OK",
            checked_at=datetime.now(timezone.utc),
        )

    monkeypatch.setattr(CDNService, "_perform_health_probe", fake_probe)

    monitor = CDNHealthMonitor(SessionLocal, interval_seconds=60)
    monitor._execute_cycle()

    with SessionLocal() as session:
        endpoint = session.get(models.CDNEndpoint, endpoint_id)
        assert endpoint is not None
        assert endpoint.health_status == CDNHealthStatus.HEALTHY.value
        logs = (
            session.query(models.AuditLog)
            .filter(models.AuditLog.action == "health_recovered")
            .order_by(models.AuditLog.created_at.asc())
            .all()
        )
        assert logs, "expected health recovery audit log"
        assert logs[0].target_id == str(endpoint_id)


def test_monitor_config_update_clamps_interval_and_logs(monkeypatch):
    get_settings.cache_clear()
    try:
        with SessionLocal() as session:
            service = CDNMonitorConfigService(session)

            persist_args: dict[str, object] = {}

            def fake_persist(self, *, enabled: bool, interval_seconds: int) -> bool:
                persist_args["enabled"] = enabled
                persist_args["interval_seconds"] = interval_seconds
                return True

            monkeypatch.setattr(CDNMonitorConfigService, "_persist_env", fake_persist)

            result = service.update_config(enabled=True, interval_seconds=10)
            assert result.enabled is True
            assert result.interval_seconds == 30
            assert persist_args == {"enabled": True, "interval_seconds": 30}

            settings = get_settings()
            assert settings.cdn_health_monitor_enabled is True
            assert settings.cdn_health_monitor_interval_seconds == 30

            logs = (
                session.query(models.AuditLog)
                .filter(models.AuditLog.action == "health_monitor_config")
                .order_by(models.AuditLog.created_at.asc())
                .all()
            )
            assert logs, "expected health monitor config audit log"
            payload = logs[0].payload or {}
            assert payload.get("enabled") is True
            assert payload.get("interval_seconds") == 30
    finally:
        get_settings.cache_clear()


def test_monitor_config_update_caps_upper_bound(monkeypatch):
    get_settings.cache_clear()
    try:
        with SessionLocal() as session:
            service = CDNMonitorConfigService(session)

            monkeypatch.setattr(CDNMonitorConfigService, "_persist_env", lambda self, **_: True)

            result = service.update_config(enabled=False, interval_seconds=5000)
            assert result.enabled is False
            assert result.interval_seconds == 3600

            config = service.get_config()
            assert config.enabled is False
            assert config.interval_seconds == 3600
    finally:
        get_settings.cache_clear()


def test_should_enable_monitor_requires_enabled_flag(monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    assert should_enable_monitor(enabled=False, environment="production") is False


def test_should_enable_monitor_skips_test_environment(monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    assert should_enable_monitor(enabled=True, environment="  TEST  ") is False


def test_should_enable_monitor_disables_when_pytest_running(monkeypatch):
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "tests/test_cdn_service.py::dummy")
    assert should_enable_monitor(enabled=True, environment="production") is False


def test_monitor_config_persist_env_returns_false_when_missing(monkeypatch, tmp_path):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.chdir(tmp_path)

    with SessionLocal() as session:
        service = CDNMonitorConfigService(session)
        result = service._persist_env(enabled=True, interval_seconds=120)

    assert result is False
    assert not (tmp_path / ".env").exists()


def test_monitor_config_persist_env_writes_values(monkeypatch, tmp_path):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.chdir(tmp_path)

    env_path = tmp_path / ".env"
    env_path.write_text("FOO=BAR\nVMP_CDN_HEALTH_MONITOR_ENABLED=false\n", encoding="utf-8")

    with SessionLocal() as session:
        service = CDNMonitorConfigService(session)
        result = service._persist_env(enabled=True, interval_seconds=75)

    assert result is True
    lines = env_path.read_text(encoding="utf-8").strip().splitlines()
    assert "FOO=BAR" in lines
    assert "VMP_CDN_HEALTH_MONITOR_ENABLED=true" in lines
    assert "VMP_CDN_HEALTH_MONITOR_INTERVAL=75" in lines


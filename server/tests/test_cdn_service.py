from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.db import CDNEndpointStatus, CDNTaskStatus, CDNTaskType
from app.db.session import SessionLocal
from app.services.cdn import CDNService, DeploymentConfig, DeploymentError, DeploymentTarget


class _FakeDeployer:
    def __init__(self, *, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.calls: list[tuple[DeploymentTarget, DeploymentConfig]] = []

    def deploy(self, target: DeploymentTarget, config: DeploymentConfig) -> None:  # type: ignore[override]
        self.calls.append((target, config))
        if self.should_fail:
            raise DeploymentError("boom")


def _create_endpoint(service: CDNService) -> int:
    endpoint = service.create_endpoint(
        name="Edge-1",
        domain="cdn.example.com",
        provider="ExampleCDN",
        origin="origin.internal",
        host="203.0.113.10",
        ssh_username="root",
        ssh_password="password123",
        ssh_port=22,
        listen_port=443,
        origin_port=8443,
        deployment_mode="http",
        edge_token="edge-token",
    )
    return endpoint.id


def test_create_endpoint_encrypts_credentials():
    fake = _FakeDeployer()
    with SessionLocal() as session:
        service = CDNService(session, deployer=fake)
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
    with SessionLocal() as session:
        service = CDNService(session, deployer=fake)
        endpoint_id = _create_endpoint(service)

        task = service.deploy_endpoint(endpoint_id, allow_http=True)
        assert task.status == CDNTaskStatus.COMPLETED.value
        assert task.task_type == CDNTaskType.DEPLOY.value
        assert task.message == "Deployment succeeded"

        refreshed = service.get_endpoint(endpoint_id)
        assert refreshed is not None
        assert refreshed.status == CDNEndpointStatus.ACTIVE.value
        assert refreshed.last_deploy_status == CDNTaskStatus.COMPLETED.value
        assert refreshed.last_deployed_at is not None
        assert refreshed.updated_at is not None
        assert refreshed.listen_port == 443

        assert len(fake.calls) == 1
        target, config = fake.calls[0]
        assert target.host == "203.0.113.10"
        assert target.username == "root"
        assert config.mode == "http"
        assert config.allow_http is True
        assert config.listen_port == 443
        assert config.origin_port == 8443

        assert isinstance(task.completed_at, datetime)
        if task.completed_at:
            assert task.completed_at.tzinfo is None or task.completed_at.tzinfo == timezone.utc


def test_deploy_endpoint_failure_marks_endpoint_error():
    fake = _FakeDeployer(should_fail=True)
    with SessionLocal() as session:
        service = CDNService(session, deployer=fake)
        endpoint_id = _create_endpoint(service)

        with pytest.raises(DeploymentError):
            service.deploy_endpoint(endpoint_id)

        refreshed = service.get_endpoint(endpoint_id)
        assert refreshed is not None
        assert refreshed.status == CDNEndpointStatus.ERROR.value
        assert refreshed.last_deploy_status == CDNTaskStatus.FAILED.value
        assert refreshed.last_deployed_at is not None

        tasks = service.list_recent_tasks(limit=5)
        assert tasks
        assert tasks[0].status == CDNTaskStatus.FAILED.value


def test_manual_deploy_task_not_allowed():
    fake = _FakeDeployer()
    with SessionLocal() as session:
        service = CDNService(session, deployer=fake)
        endpoint_id = _create_endpoint(service)

        with pytest.raises(ValueError) as exc:
            service.create_task(endpoint_id=endpoint_id, task_type=CDNTaskType.DEPLOY)
        assert str(exc.value) == "unsupported_manual_deploy"

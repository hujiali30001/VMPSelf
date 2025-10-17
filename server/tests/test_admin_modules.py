from __future__ import annotations

from fastapi.testclient import TestClient

from app.db import (
    AdminUser,
    CDNEndpoint,
    CDNEndpointStatus,
    CDNTask,
    CDNTaskStatus,
    SoftwarePackage,
    SoftwarePackageStatus,
    SoftwareSlot,
    SoftwareSlotStatus,
)
from app.db.session import SessionLocal
from app.main import app
from app.services import security

BASIC_AUTH = ("admin", "change-me")


def test_admin_cdn_module_flow():
    client = TestClient(app)

    create_resp = client.post(
        "/admin/cdn/endpoints",
        data={
            "name": "公网加速",
            "domain": "cdn.example.com",
            "provider": "测试服务商",
            "origin": "origin.example.internal",
        },
        auth=BASIC_AUTH,
        follow_redirects=False,
    )
    assert create_resp.status_code == 303

    with SessionLocal() as session:
        endpoint = session.query(CDNEndpoint).filter_by(domain="cdn.example.com").one()
        endpoint_id = endpoint.id
        assert endpoint.provider == "测试服务商"
        assert endpoint.status == CDNEndpointStatus.ACTIVE.value

    pause_resp = client.post(
        f"/admin/cdn/endpoints/{endpoint_id}/status",
        data={"status": "paused"},
        auth=BASIC_AUTH,
        follow_redirects=False,
    )
    assert pause_resp.status_code == 303

    with SessionLocal() as session:
        refreshed = session.get(CDNEndpoint, endpoint_id)
        assert refreshed is not None
        assert refreshed.status == CDNEndpointStatus.PAUSED.value

    task_resp = client.post(
        f"/admin/cdn/endpoints/{endpoint_id}/tasks",
        data={"task_type": "purge", "payload": "/assets"},
        auth=BASIC_AUTH,
        follow_redirects=False,
    )
    assert task_resp.status_code == 303

    with SessionLocal() as session:
        tasks = session.query(CDNTask).filter_by(endpoint_id=endpoint_id).all()
        assert tasks
        assert any(task.status == CDNTaskStatus.COMPLETED.value for task in tasks)

    response = client.get("/admin/cdn", auth=BASIC_AUTH)
    assert response.status_code == 200


def test_admin_software_module_flow():
    client = TestClient(app)

    create_slot = client.post(
        "/admin/software/slots",
        data={
            "code": "desktop",
            "name": "桌面客户端",
            "product_line": "PC",
            "channel": "stable",
            "gray_ratio": "10",
            "notes": "默认灰度 10%",
        },
        auth=BASIC_AUTH,
        follow_redirects=False,
    )
    assert create_slot.status_code == 303

    with SessionLocal() as session:
        slot = session.query(SoftwareSlot).filter_by(code="desktop").one()
        slot_id = slot.id
        assert slot.status == SoftwareSlotStatus.ACTIVE.value
        assert slot.gray_ratio == 10

    pause_slot = client.post(
        f"/admin/software/slots/{slot_id}/status",
        data={"status": "paused"},
        auth=BASIC_AUTH,
        follow_redirects=False,
    )
    assert pause_slot.status_code == 303

    package_resp = client.post(
        f"/admin/software/slots/{slot_id}/packages",
        data={
            "version": "1.0.0",
            "file_url": "https://download.example.com/package.zip",
            "checksum": "sha256:abc123",
            "release_notes": "首次发布",
            "promote": "1",
            "mark_critical": "1",
        },
        auth=BASIC_AUTH,
        follow_redirects=False,
    )
    assert package_resp.status_code == 303

    with SessionLocal() as session:
        refreshed_slot = session.get(SoftwareSlot, slot_id)
        assert refreshed_slot is not None
        assert refreshed_slot.status == SoftwareSlotStatus.PAUSED.value
        assert refreshed_slot.current_package is not None
        package = refreshed_slot.current_package
        package_id = package.id
        assert package.status == SoftwarePackageStatus.ACTIVE.value
        assert package.is_critical is True

    retire_resp = client.post(
        f"/admin/software/packages/{package_id}/retire",
        data={},
        auth=BASIC_AUTH,
        follow_redirects=False,
    )
    assert retire_resp.status_code == 303

    with SessionLocal() as session:
        retired_package = session.get(SoftwarePackage, package_id)
        assert retired_package is not None
        assert retired_package.status == SoftwarePackageStatus.RETIRED.value

    response = client.get("/admin/software", auth=BASIC_AUTH)
    assert response.status_code == 200
    html = response.text
    assert "桌面客户端" in html
    assert "安装包" in html


def test_admin_settings_module_flow():
    client = TestClient(app)

    create_resp = client.post(
        "/admin/settings/admins",
        data={
            "username": "ops",
            "role": "ops",
            "password": "OpsPass123!",
            "confirm_password": "OpsPass123!",
        },
        auth=BASIC_AUTH,
        follow_redirects=False,
    )
    assert create_resp.status_code == 303

    with SessionLocal() as session:
        admin = session.query(AdminUser).filter_by(username="ops").one()
        admin_id = admin.id
        original_hash = admin.password_hash
        assert admin.is_active is True

    disable_resp = client.post(
        f"/admin/settings/admins/{admin_id}/status",
        data={"is_active": "false"},
        auth=BASIC_AUTH,
        follow_redirects=False,
    )
    assert disable_resp.status_code == 303

    reset_resp = client.post(
        f"/admin/settings/admins/{admin_id}/password",
        data={"password": "AnotherPass123!", "confirm_password": "AnotherPass123!"},
        auth=BASIC_AUTH,
        follow_redirects=False,
    )
    assert reset_resp.status_code == 303

    with SessionLocal() as session:
        updated = session.get(AdminUser, admin_id)
        assert updated is not None
        assert updated.is_active is False
        assert updated.password_hash != original_hash
        assert security.verify_password("AnotherPass123!", updated.password_hash) is True

    response = client.get("/admin/settings", auth=BASIC_AUTH)
    assert response.status_code == 200
    html = response.text
    assert "管理员列表" in html
    assert "ops" in html

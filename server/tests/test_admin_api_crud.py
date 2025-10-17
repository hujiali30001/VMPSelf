from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Tuple

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db import models
from app.db.session import SessionLocal
from app.main import app
from app.services.license_service import LicenseService
from app.services.user_service import UserService

BASIC_AUTH: Tuple[str, str] = ("admin", "change-me")


def _create_license(session: Session, card_code: str, ttl_days: int = 30) -> models.License:
    service = LicenseService(session)
    license_obj = service.create_license(card_code, ttl_days)
    session.refresh(license_obj)
    return license_obj


def test_user_service_delete_unbinds_license():
    with SessionLocal() as session:
        license_obj = _create_license(session, "USER-DEL-001", ttl_days=0)
        user = UserService(session).register("user_del", "Password123!", license_obj.card_code)

        assert license_obj.user is not None

        assert UserService(session).delete_user(user.id) is True
        session.refresh(license_obj)
        assert license_obj.user is None
        assert license_obj.bound_fingerprint is None
        assert license_obj.status == models.LicenseStatus.UNUSED.value


def test_license_service_delete_requires_force_when_active():
    with SessionLocal() as session:
        license_obj = _create_license(session, "LIC-DEL-001", ttl_days=0)
        license_obj.status = models.LicenseStatus.ACTIVE.value
        activation = models.Activation(
            license=license_obj,
            device_fingerprint="device-123",
            token="token",
            last_seen=datetime.now(timezone.utc),
        )
        session.add(activation)
        session.commit()

        service = LicenseService(session)
        with pytest.raises(ValueError):
            service.delete_license(license_obj.card_code)

        assert service.delete_license(license_obj.card_code, force=True) is True
        assert service.get_license(license_obj.card_code) is None


def test_admin_api_user_crud_flow():
    client = TestClient(app)

    with SessionLocal() as session:
        primary_license = _create_license(session, "API-USER-001", ttl_days=30)
        secondary_license = _create_license(session, "API-USER-002", ttl_days=30)
        user = UserService(session).register("api_user", "StrongPass123!", primary_license.card_code)
        session.refresh(primary_license)
        session.refresh(secondary_license)
        user_id = user.id
        primary_code = primary_license.card_code
        secondary_code = secondary_license.card_code

    list_resp = client.get("/admin/api/users", auth=BASIC_AUTH)
    assert list_resp.status_code == 200
    data = list_resp.json()
    assert data["total"] >= 1

    detail_resp = client.get(f"/admin/api/users/{user_id}", auth=BASIC_AUTH)
    assert detail_resp.status_code == 200
    assert detail_resp.json()["card_code"] == primary_code

    patch_resp = client.patch(
        f"/admin/api/users/{user_id}",
        auth=BASIC_AUTH,
        json={"username": "api_user_new", "card_code": secondary_code},
    )
    assert patch_resp.status_code == 200
    patched = patch_resp.json()
    assert patched["username"] == "api_user_new"
    assert patched["card_code"] == secondary_code

    with SessionLocal() as session:
        refreshed_primary = (
            session.query(models.License).filter(models.License.card_code == primary_code).first()
        )
        refreshed_secondary = (
            session.query(models.License).filter(models.License.card_code == secondary_code).first()
        )
        assert refreshed_primary is not None and refreshed_primary.user is None
        assert refreshed_secondary is not None and refreshed_secondary.user is not None

    delete_resp = client.delete(f"/admin/api/users/{user_id}", auth=BASIC_AUTH)
    assert delete_resp.status_code == 204

    missing = client.get(f"/admin/api/users/{user_id}", auth=BASIC_AUTH)
    assert missing.status_code == 404


def test_admin_dashboard_renders_with_recent_data():
    client = TestClient(app)

    with SessionLocal() as session:
        license_obj = _create_license(session, "DASH-0001", ttl_days=7)
        license_obj.expire_at = datetime.now(timezone.utc) + timedelta(days=3)
        session.commit()

        UserService(session).register("dash_user", "DashPass123!", license_obj.card_code)

    response = client.get("/admin/", auth=BASIC_AUTH)
    assert response.status_code == 200

    html = response.text
    assert "控制台总览" in html
    assert "dash_user" in html
    assert "DASH-0001" in html
    assert "即将过期" in html


def test_admin_api_license_crud_flow():
    client = TestClient(app)

    create_resp = client.post(
        "/admin/api/licenses",
        auth=BASIC_AUTH,
        json={"card_code": "API-LIC-001", "ttl_days": 5},
    )
    assert create_resp.status_code == 201
    created_payload = create_resp.json()
    assert created_payload["quantity"] == 1
    assert created_payload["batch_id"]
    created = created_payload["items"][0]
    card_code = created["card_code"]

    list_resp = client.get(
        "/admin/api/licenses",
        auth=BASIC_AUTH,
        params={"search": card_code},
    )
    assert list_resp.status_code == 200
    assert list_resp.json()["total"] >= 1

    patch_resp = client.patch(
        f"/admin/api/licenses/{card_code}",
        auth=BASIC_AUTH,
        json={"status": "revoked"},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "revoked"

    delete_resp = client.delete(f"/admin/api/licenses/{card_code}", auth=BASIC_AUTH)
    assert delete_resp.status_code == 204

    missing = client.get(f"/admin/api/licenses/{card_code}", auth=BASIC_AUTH)
    assert missing.status_code == 404

    with SessionLocal() as session:
        active_license = _create_license(session, "API-LIC-002", ttl_days=0)
        active_license.status = models.LicenseStatus.ACTIVE.value
        activation = models.Activation(
            license=active_license,
            device_fingerprint="force-device",
            token="token",
            last_seen=datetime.now(timezone.utc),
        )
        session.add(activation)
        session.commit()

    cannot_delete = client.delete("/admin/api/licenses/API-LIC-002", auth=BASIC_AUTH)
    assert cannot_delete.status_code == 400
    assert cannot_delete.json()["detail"] == "license_active"

    force_delete = client.delete(
        "/admin/api/licenses/API-LIC-002",
        auth=BASIC_AUTH,
        params={"force": "true"},
    )
    assert force_delete.status_code == 204


def test_admin_api_license_batch_with_type_and_filter():
    client = TestClient(app)

    with SessionLocal() as session:
        card_type = models.LicenseCardType(
            code="month",
            display_name="月卡",
            default_duration_days=30,
            card_prefix="M-",
            color="#6366f1",
            is_active=True,
        )
        session.add(card_type)
        session.commit()

    batch_resp = client.post(
        "/admin/api/licenses",
        auth=BASIC_AUTH,
        json={
            "type_code": "month",
            "quantity": 3,
            "custom_prefix": "VIP-",
            "custom_ttl_days": 45,
        },
    )
    assert batch_resp.status_code == 201
    payload = batch_resp.json()
    assert payload["quantity"] == 3
    assert len(payload["items"]) == 3
    for item in payload["items"]:
        assert item["card_type"]["code"] == "month"
        assert item["card_prefix"] == "VIP-"
        assert item["custom_duration_days"] == 45

    sample_code = payload["items"][0]["card_code"]
    list_resp = client.get(
        "/admin/api/licenses",
        auth=BASIC_AUTH,
        params={"type_code": "month", "search": sample_code[:5]},
    )
    assert list_resp.status_code == 200
    data = list_resp.json()
    assert data["total"] >= 1
    assert all(item["card_type"]["code"] == "month" for item in data["items"])
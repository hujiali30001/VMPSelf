from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.db import models
from app.db.session import SessionLocal
from app.main import app

DEFAULT_SLOT_CODE = "default-slot"


def _ensure_license(card_code: str, *, status: str = None, bind_activation: bool = False) -> models.License:
    with SessionLocal() as session:
        slot = session.query(models.SoftwareSlot).filter_by(code=DEFAULT_SLOT_CODE).one()
        license_obj = models.License(
            card_code=card_code,
            secret="secret-key",
            status=status or models.LicenseStatus.UNUSED.value,
            expire_at=datetime.now(timezone.utc) + timedelta(days=30),
            software_slot=slot,
        )
        session.add(license_obj)
        session.flush()

        if bind_activation:
            license_obj.status = models.LicenseStatus.ACTIVE.value
            license_obj.bound_fingerprint = "fp-test"
            activation = models.Activation(
                license=license_obj,
                device_fingerprint="fp-test",
                token="token-value",
                activated_at=datetime.now(timezone.utc),
            )
            session.add(activation)

        session.commit()
        session.refresh(license_obj)
        return license_obj


def _create_package(slot: models.SoftwareSlot, version: str, status: str) -> models.SoftwarePackage:
    package = models.SoftwarePackage(
        slot=slot,
        version=version,
        status=status,
        file_url=f"https://cdn.example.com/{version}.zip",
        checksum="sha256:test",
        release_notes="Test build",
        is_critical=False,
    )
    return package


def test_license_detail_endpoint_returns_info():
    license_obj = _ensure_license("DETAIL-001")
    client = TestClient(app)

    response = client.get(
        "/api/v1/license/detail",
        params={"card_code": license_obj.card_code},
    )
    assert response.status_code == 200

    data = response.json()
    assert data["card_code"] == license_obj.card_code
    assert data["status"] == models.LicenseStatus.UNUSED.value
    assert data["slot_code"] == DEFAULT_SLOT_CODE
    assert data["card_type"] is None


def test_license_reset_endpoint_clears_activation():
    license_obj = _ensure_license("RESET-001", bind_activation=True)
    client = TestClient(app)

    response = client.post("/api/v1/license/reset", json={"card_code": license_obj.card_code})
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

    with SessionLocal() as session:
        refreshed = session.query(models.License).filter_by(card_code=license_obj.card_code).one()
        assert refreshed.status == models.LicenseStatus.UNUSED.value
        assert refreshed.bound_fingerprint is None
        assert not refreshed.activations


def test_license_config_endpoint_exposes_settings():
    client = TestClient(app)
    response = client.get("/api/v1/license/config")
    assert response.status_code == 200
    data = response.json()
    assert data["heartbeat_interval_seconds"] > 0
    assert data["token_ttl_minutes"] > 0
    assert data["offline_ttl_minutes"] >= data["token_ttl_minutes"]


def test_list_slots_includes_current_package():
    with SessionLocal() as session:
        slot = session.query(models.SoftwareSlot).filter_by(code=DEFAULT_SLOT_CODE).one()
        package = _create_package(slot, "1.2.3", models.SoftwarePackageStatus.ACTIVE.value)
        session.add(package)
        session.flush()
        link = models.SoftwareSlotCurrentPackage(slot=slot, package=package)
        session.add(link)
        slot.updated_at = datetime.now(timezone.utc)
        session.commit()

    client = TestClient(app)
    response = client.get("/api/v1/software/slots")
    assert response.status_code == 200
    data = response.json()
    assert any(item["code"] == DEFAULT_SLOT_CODE for item in data)
    default_slot = next(item for item in data if item["code"] == DEFAULT_SLOT_CODE)
    assert default_slot["current_package_version"] == "1.2.3"


def test_list_packages_filters_by_status():
    with SessionLocal() as session:
        slot = session.query(models.SoftwareSlot).filter_by(code=DEFAULT_SLOT_CODE).one()
        active_pkg = _create_package(slot, "2.0.0", models.SoftwarePackageStatus.ACTIVE.value)
        draft_pkg = _create_package(slot, "2.1.0", models.SoftwarePackageStatus.DRAFT.value)
        session.add_all([active_pkg, draft_pkg])
        session.commit()

    client = TestClient(app)
    response = client.get(
        "/api/v1/software/packages",
        params={"slot_code": DEFAULT_SLOT_CODE},
    )
    assert response.status_code == 200
    data = response.json()
    versions = [item["version"] for item in data["items"]]
    assert "2.0.0" in versions
    assert "2.1.0" not in versions

    response_all = client.get(
        "/api/v1/software/packages",
        params={"slot_code": DEFAULT_SLOT_CODE, "status": "all"},
    )
    assert response_all.status_code == 200
    all_versions = [item["version"] for item in response_all.json()["items"]]
    assert {"2.0.0", "2.1.0"}.issubset(set(all_versions))

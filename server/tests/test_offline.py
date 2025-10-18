from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.db import models
from app.db.session import SessionLocal
from app.main import app
from app.services.security import sign_message

DEFAULT_SLOT_CODE = "default-slot"


def _create_license(card_code: str, secret: str) -> models.License:
    with SessionLocal() as session:
        slot = session.query(models.SoftwareSlot).filter_by(code=DEFAULT_SLOT_CODE).one()
        license_obj = models.License(
            card_code=card_code,
            secret=secret,
            expire_at=datetime.now(timezone.utc) + timedelta(days=30),
            status=models.LicenseStatus.UNUSED.value,
            software_slot=slot,
        )
        session.add(license_obj)
        session.commit()
        session.refresh(license_obj)
        return license_obj


def test_generate_offline_license():
    license_obj = _create_license("CARD-001", "secret-key")
    client = TestClient(app)

    expires = datetime.now(timezone.utc) + timedelta(hours=12)
    fingerprint = "FP-12345"
    timestamp = int(expires.timestamp())
    signature = sign_message(
        f"{license_obj.card_code}|{fingerprint}|{timestamp}",
        shared_secret=license_obj.secret,
    )

    response = client.post(
        "/api/v1/license/offline",
        json={
            "card_code": license_obj.card_code,
            "fingerprint": fingerprint,
            "expires_at": expires.isoformat(),
            "signature": signature,
        },
    )

    assert response.status_code == 200
    data = response.json()
    blob = json.loads(data["license_blob"])
    assert blob["card_code"] == license_obj.card_code
    assert blob["fingerprint"] == fingerprint
    assert "token" in blob
    assert "issued_at" in blob

    expected_signature = sign_message(data["license_blob"], shared_secret=license_obj.secret)
    assert data["signature"] == expected_signature

    with SessionLocal() as session:
        logs = session.query(models.AuditLog).filter(models.AuditLog.license_id == license_obj.id).all()
        assert any(log.action == "offline_issue" for log in logs)


def test_admin_generate_offline_license_success():
    license_obj = _create_license("ADMIN-CARD-1", "admin-secret")
    client = TestClient(app)

    response = client.post(
        f"/admin/licenses/{license_obj.card_code}/offline",
        data={
            "fingerprint": "ADMIN-FP-1",
            "ttl_days": "3",
        },
        auth=("admin", "change-me"),
    )

    assert response.status_code == 200
    html = response.text
    assert "离线授权已生成" in html
    assert "ADMIN-FP-1" in html
    assert "license-blob" in html
    assert "license-signature" in html
    assert "下载离线包" in html

    with SessionLocal() as session:
        log = (
            session.query(models.AuditLog)
            .filter(models.AuditLog.license_id == license_obj.id, models.AuditLog.action == "offline_generate")
            .order_by(models.AuditLog.created_at.desc())
            .first()
        )
        assert log is not None
        assert "ADMIN-FP-1" in (log.message or "")


def test_admin_generate_offline_license_validation_error():
    license_obj = _create_license("ADMIN-CARD-2", "admin-secret")
    client = TestClient(app)

    response = client.post(
        f"/admin/licenses/{license_obj.card_code}/offline",
        data={
            "fingerprint": "ADMIN-FP-2",
            "ttl_days": "0",
        },
        auth=("admin", "change-me"),
    )

    assert response.status_code == 200
    html = response.text
    assert "离线授权有效期必须大于 0 天" in html
    assert "license-blob" not in html

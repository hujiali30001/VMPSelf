from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.db import models
from app.db.session import SessionLocal
from app.main import app
from app.services.security import sign_message


def _create_license(card_code: str, secret: str) -> models.License:
    with SessionLocal() as session:
        license_obj = models.License(
            card_code=card_code,
            secret=secret,
            expire_at=datetime.now(timezone.utc) + timedelta(days=30),
            status=models.LicenseStatus.UNUSED.value,
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
        assert any(log.event_type == "offline_issue" for log in logs)

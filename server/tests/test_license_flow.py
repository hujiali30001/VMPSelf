from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.db import models
from app.db.session import SessionLocal
from app.main import app
from app.services.security import sign_message

DEFAULT_SLOT_CODE = "default-slot"


def _create_license(card_code: str, secret: str, ttl_days: int = 30) -> None:
    with SessionLocal() as session:
        slot = session.query(models.SoftwareSlot).filter_by(code=DEFAULT_SLOT_CODE).one()
        license_obj = models.License(
            card_code=card_code,
            secret=secret,
            expire_at=datetime.now(timezone.utc) + timedelta(days=ttl_days),
            status=models.LicenseStatus.UNUSED.value,
            software_slot=slot,
        )
        session.add(license_obj)
        session.commit()


def test_activation_heartbeat_and_revoke_flow():
    card_code = "CARD-TEST"
    secret = "secret-key"
    fingerprint = "fp-12345"
    _create_license(card_code, secret)

    client = TestClient(app)

    timestamp = int(datetime.now(timezone.utc).timestamp())
    activation_signature = sign_message(
        f"{card_code}|{fingerprint}|{timestamp}",
        shared_secret=secret,
    )
    activate_resp = client.post(
        "/api/v1/license/activate",
        json={
            "card_code": card_code,
            "fingerprint": fingerprint,
            "timestamp": timestamp,
            "signature": activation_signature,
            "slot_code": DEFAULT_SLOT_CODE,
        },
    )

    assert activate_resp.status_code == 200
    activate_json = activate_resp.json()
    token = activate_json["token"]
    assert activate_json["heartbeat_interval_seconds"] > 0

    with SessionLocal() as session:
        license_obj = session.query(models.License).filter_by(card_code=card_code).one()
        assert license_obj.status == models.LicenseStatus.ACTIVE.value
        assert license_obj.bound_fingerprint == fingerprint
        assert license_obj.activations
        assert license_obj.activations[0].token == token

    heartbeat_ts = timestamp + 60
    heartbeat_signature = sign_message(
        f"{card_code}|{fingerprint}|{heartbeat_ts}",
        shared_secret=secret,
    )

    heartbeat_resp = client.post(
        "/api/v1/license/heartbeat",
        json={
            "token": token,
            "fingerprint": fingerprint,
            "timestamp": heartbeat_ts,
            "signature": heartbeat_signature,
        },
    )
    assert heartbeat_resp.status_code == 200

    with SessionLocal() as session:
        activation = session.query(models.Activation).filter_by(token=token).one()
        assert activation.last_seen is not None

    revoke_resp = client.post(
        "/api/v1/license/revoke",
        json={"card_code": card_code},
    )
    assert revoke_resp.status_code == 200

    with SessionLocal() as session:
        license_obj = session.query(models.License).filter_by(card_code=card_code).one()
        assert license_obj.status == models.LicenseStatus.REVOKED.value
        logs = session.query(models.AuditLog).filter_by(license_id=license_obj.id).all()
        assert any(log.event_type == "revoke" for log in logs)

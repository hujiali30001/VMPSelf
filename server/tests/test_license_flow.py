from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.db import models
from app.db.session import SessionLocal
from app.main import app
from app.services.licensing import LicenseService
from app.services.security import sign_message

DEFAULT_SLOT_CODE = "default-slot"
DEFAULT_SLOT_SECRET = "default-slot-secret"


def _create_license(card_code: str, secret: str, ttl_days: int = 30) -> None:
    with SessionLocal() as session:
        slot = session.query(models.SoftwareSlot).filter_by(code=DEFAULT_SLOT_CODE).one()
        license_obj = models.License(
            card_code=card_code,
            secret=secret,
            expire_at=None,
            status=models.LicenseStatus.UNUSED.value,
            software_slot=slot,
            custom_duration_days=ttl_days,
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
        assert license_obj.expire_at is not None
        expire_at = license_obj.expire_at
        if expire_at.tzinfo is None:
            expire_at = expire_at.replace(tzinfo=timezone.utc)
        expected_expire = datetime.fromtimestamp(timestamp, timezone.utc) + timedelta(days=30)
        assert abs((expire_at - expected_expire).total_seconds()) < 5
        assert license_obj.secret_migrated is False

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

    with SessionLocal() as session:
        service = LicenseService(session)
        assert service.revoke(card_code) is True
        license_obj = session.query(models.License).filter_by(card_code=card_code).one()
        assert license_obj.status == models.LicenseStatus.REVOKED.value
        logs = session.query(models.AuditLog).filter_by(license_id=license_obj.id).all()
        assert any(log.action == "revoke" for log in logs)


def test_activation_with_slot_secret_marks_migrated():
    card_code = "CARD-SLOT"
    legacy_secret = "legacy-secret"
    fingerprint = "fp-slot"
    _create_license(card_code, legacy_secret)

    client = TestClient(app)
    timestamp = int(datetime.now(timezone.utc).timestamp())
    activation_signature = sign_message(
        f"{card_code}|{fingerprint}|{timestamp}",
        shared_secret=DEFAULT_SLOT_SECRET,
    )

    resp = client.post(
        "/api/v1/license/activate",
        json={
            "card_code": card_code,
            "fingerprint": fingerprint,
            "timestamp": timestamp,
            "signature": activation_signature,
            "slot_code": DEFAULT_SLOT_CODE,
            "use_slot_secret": True,
        },
    )

    assert resp.status_code == 200
    token = resp.json()["token"]

    with SessionLocal() as session:
        license_obj = session.query(models.License).filter_by(card_code=card_code).one()
        assert license_obj.secret_migrated is True
        assert license_obj.bound_fingerprint == fingerprint
        assert license_obj.status == models.LicenseStatus.ACTIVE.value
        logs = session.query(models.AuditLog).filter_by(license_id=license_obj.id).all()
        assert any(log.action == "activate_slot_secret" for log in logs)

    heartbeat_ts = timestamp + 120
    heartbeat_signature = sign_message(
        f"{card_code}|{fingerprint}|{heartbeat_ts}",
        shared_secret=DEFAULT_SLOT_SECRET,
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


def test_offline_license_uses_matching_secret():
    card_code_slot = "CARD-OFFLINE-SLOT"
    card_code_legacy = "CARD-OFFLINE-LEGACY"
    legacy_secret = "legacy-offline"
    fingerprint = "fp-offline"

    _create_license(card_code_slot, legacy_secret)
    _create_license(card_code_legacy, legacy_secret)

    client = TestClient(app)

    # slot secret request
    expires_slot = datetime.now(timezone.utc) + timedelta(hours=2)
    slot_signature = sign_message(
        f"{card_code_slot}|{fingerprint}|{int(expires_slot.timestamp())}",
        shared_secret=DEFAULT_SLOT_SECRET,
    )
    slot_resp = client.post(
        "/api/v1/license/offline",
        json={
            "card_code": card_code_slot,
            "fingerprint": fingerprint,
            "expires_at": expires_slot.isoformat(),
            "signature": slot_signature,
        },
    )
    assert slot_resp.status_code == 200
    slot_payload = slot_resp.json()
    assert slot_payload["signature"] == sign_message(
        slot_payload["license_blob"],
        shared_secret=DEFAULT_SLOT_SECRET,
    )

    with SessionLocal() as session:
        license_slot = session.query(models.License).filter_by(card_code=card_code_slot).one()
        assert license_slot.secret_migrated is True

    # legacy secret request
    expires_legacy = datetime.now(timezone.utc) + timedelta(hours=2)
    legacy_signature = sign_message(
        f"{card_code_legacy}|{fingerprint}|{int(expires_legacy.timestamp())}",
        shared_secret=legacy_secret,
    )
    legacy_resp = client.post(
        "/api/v1/license/offline",
        json={
            "card_code": card_code_legacy,
            "fingerprint": fingerprint,
            "expires_at": expires_legacy.isoformat(),
            "signature": legacy_signature,
        },
    )
    assert legacy_resp.status_code == 200
    legacy_payload = legacy_resp.json()
    assert legacy_payload["signature"] == sign_message(
        legacy_payload["license_blob"],
        shared_secret=legacy_secret,
    )

    with SessionLocal() as session:
        license_legacy = session.query(models.License).filter_by(card_code=card_code_legacy).one()
        assert license_legacy.secret_migrated is False

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from app.db import models
from app.db.session import SessionLocal
from app.services.license_service import LicenseService
from app.services import security

DEFAULT_SLOT_CODE = "default-slot"


def _get_default_slot(session):
    return session.query(models.SoftwareSlot).filter_by(code=DEFAULT_SLOT_CODE).one()


def test_create_license_generates_secret_and_expiry():
    with SessionLocal() as session:
        service = LicenseService(session)
        license_obj = service.create_license(None, 15, slot_code=DEFAULT_SLOT_CODE)

        assert license_obj.card_code
        assert license_obj.secret
        assert len(license_obj.secret) >= 32
        assert license_obj.status == models.LicenseStatus.UNUSED.value
        assert license_obj.expire_at is not None
        expire_at = license_obj.expire_at
        if expire_at.tzinfo is None:
            expire_at = expire_at.replace(tzinfo=timezone.utc)
        assert (expire_at - datetime.now(timezone.utc)).days >= 14

        logs = service.get_audit_logs(license_obj)
        assert any(log.event_type == "create" for log in logs)


def test_extend_expiry_pushes_date_forward():
    with SessionLocal() as session:
        now = datetime.now(timezone.utc)
        slot = _get_default_slot(session)
        license_obj = models.License(
            card_code="CARD-EXT",
            secret="secret",
            expire_at=now + timedelta(days=5),
            software_slot=slot,
        )
        session.add(license_obj)
        session.commit()

        service = LicenseService(session)
        updated = service.extend_expiry("CARD-EXT", 10)
        assert updated is not None
        assert updated.expire_at is not None
        expire_at = updated.expire_at
        if expire_at.tzinfo is None:
            expire_at = expire_at.replace(tzinfo=timezone.utc)
        assert (expire_at - now).days >= 15

        logs = service.get_audit_logs(updated)
        assert any(log.event_type == "extend" for log in logs)


def test_reset_license_clears_fingerprint_and_activations():
    with SessionLocal() as session:
        slot = _get_default_slot(session)
        license_obj = models.License(
            card_code="CARD-RESET",
            secret="secret",
            status=models.LicenseStatus.ACTIVE.value,
            bound_fingerprint="fingerprint",
            expire_at=datetime.now(timezone.utc) + timedelta(days=30),
            software_slot=slot,
        )
        activation = models.Activation(
            license=license_obj,
            device_fingerprint="fingerprint",
            token="token",
        )
        session.add(license_obj)
        session.add(activation)
        session.commit()

        service = LicenseService(session)
        assert service.reset_license("CARD-RESET") is True

        refreshed = service.get_license("CARD-RESET")
        assert refreshed is not None
        assert refreshed.bound_fingerprint is None
        assert refreshed.status == models.LicenseStatus.UNUSED.value
        assert not refreshed.activations

        logs = service.get_audit_logs(refreshed)
        assert any(log.event_type == "reset" for log in logs)


def test_generate_offline_license_respects_expiry_and_logs():
    with SessionLocal() as session:
        now = datetime.now(timezone.utc)
        slot = _get_default_slot(session)
        license_obj = models.License(
            card_code="CARD-OFFLINE",
            secret="secret-value",
            expire_at=now + timedelta(days=5),
            status=models.LicenseStatus.UNUSED.value,
            software_slot=slot,
        )
        session.add(license_obj)
        session.commit()
        session.refresh(license_obj)

        service = LicenseService(session)
        requested_expiry = now + timedelta(days=10)
        blob, signature, effective_expiry, status = service.generate_offline_license(
            license_obj.card_code,
            "device-123",
            requested_expiry,
        )

        assert status == "ok"
        assert blob is not None and signature is not None and effective_expiry is not None
        license_expiry = license_obj.expire_at
        if license_expiry and license_expiry.tzinfo is None:
            license_expiry = license_expiry.replace(tzinfo=timezone.utc)
        assert license_expiry is not None
        assert effective_expiry <= license_expiry

        payload = json.loads(blob)
        assert payload["card_code"] == license_obj.card_code
        assert payload["fingerprint"] == "device-123"
        assert payload["token"]
        assert payload["expires_at"] == effective_expiry.isoformat()

        expected_signature = security.sign_message(blob, shared_secret=license_obj.secret)
        assert signature == expected_signature

    logs = service.get_audit_logs(license_obj)
    offline_log = next((log for log in logs if log.event_type == "offline_generate"), None)
    assert offline_log is not None
    assert "device-123" in (offline_log.message or "")
    assert effective_expiry.isoformat() in (offline_log.message or "")


def test_create_licenses_with_type_and_customizations():
    with SessionLocal() as session:
        card_type = models.LicenseCardType(
            code="enterprise",
            display_name="企业授权",
            default_duration_days=180,
            card_prefix="E-",
            color="#0ea5e9",
            is_active=True,
        )
        session.add(card_type)
        session.commit()

        service = LicenseService(session)
        licenses, batch_id = service.create_licenses(
            type_code="enterprise",
            quantity=2,
            custom_prefix="VIP-",
            custom_ttl_days=200,
            slot_code=DEFAULT_SLOT_CODE,
        )

        assert batch_id
        assert len(licenses) == 2
        for license_obj in licenses:
            assert license_obj.card_type_id == card_type.id
            assert license_obj.card_prefix == "VIP-"
            assert license_obj.custom_duration_days == 200
            assert license_obj.expire_at is not None
            if license_obj.expire_at:
                expire_at = license_obj.expire_at
                if expire_at.tzinfo is None:
                    expire_at = expire_at.replace(tzinfo=timezone.utc)
                assert (expire_at - datetime.now(timezone.utc)).days >= 199

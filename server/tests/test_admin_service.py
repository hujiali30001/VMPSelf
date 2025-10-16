from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.db import models
from app.db.session import SessionLocal
from app.services.license_service import LicenseService


def test_create_license_generates_secret_and_expiry():
    with SessionLocal() as session:
        service = LicenseService(session)
        license_obj = service.create_license(None, 15)

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
        license_obj = models.License(
            card_code="CARD-EXT",
            secret="secret",
            expire_at=now + timedelta(days=5),
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
        license_obj = models.License(
            card_code="CARD-RESET",
            secret="secret",
            status=models.LicenseStatus.ACTIVE.value,
            bound_fingerprint="fingerprint",
            expire_at=datetime.now(timezone.utc) + timedelta(days=30),
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

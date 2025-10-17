from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.settings import get_settings
from app.db import models
from app.schemas import ActivationRequest, HeartbeatRequest
from app.services import security

settings = get_settings()


class LicenseService:
    def __init__(self, db: Session):
        self.db = db

    def get_license(self, card_code: str) -> Optional[models.License]:
        stmt = select(models.License).where(models.License.card_code == card_code)
        return self.db.scalar(stmt)

    def list_licenses(
        self,
        *,
        status: Optional[str] = None,
        search: Optional[str] = None,
        offset: int = 0,
        limit: int = 100,
    ) -> List[models.License]:
        offset = max(offset, 0)
        limit = max(1, min(limit, 200))

        stmt = select(models.License).order_by(models.License.created_at.desc())
        if status and status != "all":
            stmt = stmt.where(models.License.status == status)
        if search:
            stmt = stmt.where(models.License.card_code.ilike(f"%{search.strip()}%"))

        stmt = stmt.offset(offset).limit(limit)
        return list(self.db.scalars(stmt).all())

    def create_license(self, card_code: Optional[str], ttl_days: int) -> models.License:
        if card_code and not card_code.strip():
            raise ValueError("card_code must not be blank")

        code = card_code.strip() if card_code else secrets.token_hex(8).upper()
        secret = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        expires = None
        if ttl_days > 0:
            expires = now + timedelta(days=ttl_days)

        license_obj = models.License(
            card_code=code,
            secret=secret,
            expire_at=expires,
            status=models.LicenseStatus.UNUSED.value,
        )
        self.db.add(license_obj)
        self.db.flush()
        self.log_event(license_obj, "create", f"License created with ttl_days={ttl_days}")
        self.db.commit()
        self.db.refresh(license_obj)
        return license_obj

    def log_event(self, license_obj: models.License, event_type: str, message: str) -> None:
        log = models.AuditLog(
            event_type=event_type,
            license_id=license_obj.id,
            message=message,
        )
        self.db.add(log)

    def get_audit_logs(self, license_obj: models.License, limit: int = 50) -> list[models.AuditLog]:
        stmt = (
            select(models.AuditLog)
            .where(models.AuditLog.license_id == license_obj.id)
            .order_by(models.AuditLog.created_at.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def activate(self, request: ActivationRequest) -> tuple[Optional[str], Optional[datetime], str]:
        license_obj = self.get_license(request.card_code)
        if not license_obj:
            return None, None, "license_not_found"

        if not security.verify_signature(
            request.card_code,
            request.fingerprint,
            request.timestamp,
            request.signature,
            shared_secret=license_obj.secret,
        ):
            return None, None, "invalid_signature"

        now = datetime.now(timezone.utc)
        expire_at = license_obj.expire_at
        if expire_at and expire_at.tzinfo is None:
            expire_at = expire_at.replace(tzinfo=timezone.utc)

        if expire_at and expire_at < now:
            license_obj.status = models.LicenseStatus.EXPIRED.value
            self.log_event(license_obj, "license_expired", "Activation attempted on expired license")
            self.db.commit()
            return None, None, "license_expired"

        activation = next(
            (existing for existing in license_obj.activations if existing.device_fingerprint == request.fingerprint),
            None,
        )

        token, expires_at = security.issue_token(request.card_code, request.fingerprint)

        if activation:
            activation.token = token
            activation.last_seen = now
        else:
            activation = models.Activation(
                license=license_obj,
                device_fingerprint=request.fingerprint,
                token=token,
                last_seen=now,
            )
            self.db.add(activation)

        license_obj.status = models.LicenseStatus.ACTIVE.value
        license_obj.bound_fingerprint = request.fingerprint
        license_obj.updated_at = now
        self.log_event(license_obj, "activate", "License activated and token issued")
        self.db.commit()
        self.db.refresh(license_obj)
        return token, expires_at, "ok"

    def heartbeat(self, request: HeartbeatRequest) -> bool:
        activation = self.db.scalar(
            select(models.Activation).where(models.Activation.token == request.token)
        )
        if not activation:
            return False

        license_obj = activation.license

        if not security.verify_signature(
            license_obj.card_code,
            request.fingerprint,
            request.timestamp,
            request.signature,
            shared_secret=license_obj.secret,
        ):
            return False

        activation.last_seen = datetime.now(timezone.utc)
        self.log_event(license_obj, "heartbeat", "Heartbeat received")
        self.db.commit()
        return True

    def extend_expiry(self, card_code: str, extra_days: int) -> Optional[models.License]:
        if extra_days <= 0:
            raise ValueError("extra_days must be positive")

        license_obj = self.get_license(card_code)
        if not license_obj:
            return None

        now = datetime.now(timezone.utc)
        base = license_obj.expire_at
        if base is None:
            base = now
        elif base.tzinfo is None:
            base = base.replace(tzinfo=timezone.utc)

        license_obj.expire_at = base + timedelta(days=extra_days)
        license_obj.updated_at = now
        self.log_event(license_obj, "extend", f"Expiry extended by {extra_days} days")
        self.db.commit()
        self.db.refresh(license_obj)
        return license_obj

    def update_license(
        self,
        card_code: str,
        *,
        expire_at: Optional[datetime] = None,
        status: Optional[str] = None,
        bound_fingerprint: Optional[str] = None,
    ) -> models.License:
        license_obj = self.get_license(card_code)
        if not license_obj:
            raise ValueError("license_not_found")

        now = datetime.now(timezone.utc)
        changed = False

        if expire_at is not None:
            if expire_at.tzinfo is None:
                expire_at = expire_at.replace(tzinfo=timezone.utc)
            if expire_at <= now:
                raise ValueError("invalid_expiry")
            license_obj.expire_at = expire_at
            changed = True

        if status is not None and status != license_obj.status:
            valid = {item.value for item in models.LicenseStatus}
            if status not in valid:
                raise ValueError("invalid_status")
            license_obj.status = status
            changed = True

        if bound_fingerprint is not None:
            trimmed = bound_fingerprint.strip() or None
            license_obj.bound_fingerprint = trimmed
            changed = True

        if not changed:
            return license_obj

        license_obj.updated_at = now
        self.log_event(license_obj, "update", "License updated via API")
        self.db.commit()
        self.db.refresh(license_obj)
        return license_obj

    def generate_offline_license(
        self,
        card_code: str,
        fingerprint: str,
        expires_at: datetime,
    ) -> tuple[Optional[str], Optional[str], Optional[datetime], str]:
        if not fingerprint.strip():
            raise ValueError("fingerprint must not be blank")

        license_obj = self.get_license(card_code)
        if not license_obj:
            return None, None, None, "license_not_found"

        now = datetime.now(timezone.utc)
        license_expiry = license_obj.expire_at
        if license_expiry and license_expiry.tzinfo is None:
            license_expiry = license_expiry.replace(tzinfo=timezone.utc)

        if license_expiry and license_expiry < now:
            license_obj.status = models.LicenseStatus.EXPIRED.value
            self.log_event(license_obj, "license_expired", "Offline generation attempted on expired license")
            self.db.commit()
            return None, None, None, "license_expired"

        effective_expiry = expires_at
        if effective_expiry.tzinfo is None:
            effective_expiry = effective_expiry.replace(tzinfo=timezone.utc)

        if effective_expiry <= now:
            return None, None, None, "invalid_expiry"

        if license_expiry and effective_expiry > license_expiry:
            effective_expiry = license_expiry

        token, _ = security.issue_token(license_obj.card_code, fingerprint)
        payload = {
            "card_code": license_obj.card_code,
            "fingerprint": fingerprint,
            "token": token,
            "expires_at": effective_expiry.isoformat(),
            "issued_at": now.isoformat(),
        }
        license_blob = json.dumps(payload, separators=(",", ":"))
        signature = security.sign_message(license_blob, shared_secret=license_obj.secret)

        self.log_event(
            license_obj,
            "offline_generate",
            f"Offline license generated via admin for {fingerprint} until {effective_expiry.isoformat()}",
        )
        self.db.commit()
        return license_blob, signature, effective_expiry, "ok"

    def reset_license(self, card_code: str) -> bool:
        license_obj = self.get_license(card_code)
        if not license_obj:
            return False

        for activation in list(license_obj.activations):
            self.db.delete(activation)

        license_obj.bound_fingerprint = None
        license_obj.status = models.LicenseStatus.UNUSED.value
        license_obj.updated_at = datetime.now(timezone.utc)
        self.log_event(license_obj, "reset", "License reset and activations cleared")
        self.db.commit()
        return True

    def revoke(self, card_code: str) -> bool:
        license_obj = self.get_license(card_code)
        if not license_obj:
            return False

        license_obj.status = models.LicenseStatus.REVOKED.value
        license_obj.updated_at = datetime.now(timezone.utc)
        self.log_event(license_obj, "revoke", "License revoked")
        self.db.commit()
        return True

    def delete_license(self, card_code: str, *, force: bool = False) -> bool:
        license_obj = self.get_license(card_code)
        if not license_obj:
            return False

        if (
            not force
            and license_obj.status == models.LicenseStatus.ACTIVE.value
            and license_obj.activations
        ):
            raise ValueError("license_active")

        if license_obj.user:
            self.db.delete(license_obj.user)
            license_obj.user = None

        for activation in list(license_obj.activations):
            self.db.delete(activation)

        self.log_event(license_obj, "delete", "License deleted")
        self.db.delete(license_obj)
        self.db.commit()
        return True

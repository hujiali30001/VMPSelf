from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

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

    def log_event(self, license_obj: models.License, event_type: str, message: str) -> None:
        log = models.AuditLog(
            event_type=event_type,
            license_id=license_obj.id,
            message=message,
        )
        self.db.add(log)

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

    def revoke(self, card_code: str) -> bool:
        license_obj = self.get_license(card_code)
        if not license_obj:
            return False

        license_obj.status = models.LicenseStatus.REVOKED.value
        self.log_event(license_obj, "revoke", "License revoked")
        self.db.commit()
        return True

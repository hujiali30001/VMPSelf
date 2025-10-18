from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.settings import get_settings
from app.db import models
from app.schemas import ActivationRequest, HeartbeatRequest
from app.services import security
from app.services.audit import AuditActor, AuditService

settings = get_settings()


class LicenseService:
    def __init__(self, db: Session, *, actor: Optional[AuditActor] = None):
        self.db = db
        self.audit = AuditService(db)
        self._actor = actor

    def get_license(self, card_code: str) -> Optional[models.License]:
        stmt = select(models.License).where(models.License.card_code == card_code)
        return self.db.scalar(stmt)

    def list_licenses(
        self,
        *,
        status: Optional[str] = None,
        search: Optional[str] = None,
        type_code: Optional[str] = None,
        offset: int = 0,
        limit: int = 100,
    ) -> List[models.License]:
        offset = max(offset, 0)
        limit = max(1, min(limit, 200))

        stmt = (
            select(models.License)
            .options(
                selectinload(models.License.user),
                selectinload(models.License.card_type),
                selectinload(models.License.software_slot),
                selectinload(models.License.batch),
                selectinload(models.License.activations),
            )
            .order_by(models.License.created_at.desc())
        )
        if status and status != "all":
            stmt = stmt.where(models.License.status == status)
        if search:
            stmt = stmt.where(models.License.card_code.ilike(f"%{search.strip()}%"))
        if type_code:
            normalized_type = type_code.strip()
            if normalized_type == "__none__":
                stmt = stmt.where(models.License.card_type_id.is_(None))
            else:
                stmt = stmt.join(models.License.card_type).where(
                    models.LicenseCardType.code == normalized_type
                )

        stmt = stmt.offset(offset).limit(limit)
        return list(self.db.scalars(stmt).all())

    def list_batches(self, *, offset: int = 0, limit: int = 100) -> List[models.LicenseBatch]:
        offset = max(offset, 0)
        limit = max(1, min(limit, 200))
        stmt = (
            select(models.LicenseBatch)
            .options(
                selectinload(models.LicenseBatch.card_type),
            )
            .order_by(models.LicenseBatch.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def get_batch(self, batch_id: int) -> Optional[models.LicenseBatch]:
        stmt = (
            select(models.LicenseBatch)
            .options(
                selectinload(models.LicenseBatch.card_type),
                selectinload(models.LicenseBatch.licenses).selectinload(models.License.card_type),
                selectinload(models.LicenseBatch.licenses).selectinload(models.License.user),
                selectinload(models.LicenseBatch.licenses).selectinload(models.License.software_slot),
            )
            .where(models.LicenseBatch.id == batch_id)
        )
        return self.db.scalar(stmt)

    def get_batch_by_code(self, batch_code: str) -> Optional[models.LicenseBatch]:
        if not batch_code:
            return None
        normalized = batch_code.strip().upper()
        if not normalized:
            return None
        stmt = (
            select(models.LicenseBatch)
            .options(
                selectinload(models.LicenseBatch.card_type),
                selectinload(models.LicenseBatch.licenses).selectinload(models.License.card_type),
                selectinload(models.LicenseBatch.licenses).selectinload(models.License.user),
                selectinload(models.LicenseBatch.licenses).selectinload(models.License.software_slot),
            )
            .where(models.LicenseBatch.batch_code == normalized)
        )
        return self.db.scalar(stmt)

    def _normalize_card_code(self, card_code: str) -> str:
        normalized = card_code.strip()
        if not normalized:
            raise ValueError("card_code_blank")
        if len(normalized) > 64:
            raise ValueError("card_code_too_long")
        return normalized

    @staticmethod
    def _normalize_prefix(prefix: Optional[str]) -> Optional[str]:
        if prefix is None:
            return None
        trimmed = prefix.strip()
        if not trimmed:
            return None
        if len(trimmed) > 16:
            raise ValueError("prefix_too_long")
        allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        if any(char not in allowed for char in trimmed):
            raise ValueError("prefix_invalid")
        return trimmed

    def _generate_card_code(self, prefix: Optional[str]) -> str:
        token = secrets.token_hex(8).upper()
        if prefix:
            return f"{prefix}{token}"
        return token

    def _resolve_card_type(self, type_code: Optional[str]) -> Optional[models.LicenseCardType]:
        if not type_code:
            return None
        stmt = select(models.LicenseCardType).where(models.LicenseCardType.code == type_code)
        card_type = self.db.scalar(stmt)
        if not card_type:
            raise ValueError("card_type_not_found")
        if not card_type.is_active:
            raise ValueError("card_type_disabled")
        return card_type

    def _resolve_slot(self, slot_code: Optional[str]) -> models.SoftwareSlot:
        normalized = (slot_code or "").strip().lower()
        if not normalized:
            raise ValueError("slot_code_required")

        slot = self.db.scalar(select(models.SoftwareSlot).where(models.SoftwareSlot.code == normalized))
        if not slot:
            raise ValueError("slot_not_found")
        return slot

    def create_licenses(
        self,
        *,
        type_code: Optional[str] = None,
        card_code: Optional[str] = None,
        quantity: int = 1,
        custom_prefix: Optional[str] = None,
        ttl_days: Optional[int] = None,
        custom_ttl_days: Optional[int] = None,
        slot_code: Optional[str] = None,
    ) -> tuple[list[models.License], models.LicenseBatch]:
        if quantity <= 0:
            raise ValueError("quantity_invalid")
        if quantity > 500:
            raise ValueError("quantity_too_large")
        if card_code and quantity != 1:
            raise ValueError("card_code_requires_single_quantity")

        card_type = self._resolve_card_type(type_code)
        slot = self._resolve_slot(slot_code)

        prefix = self._normalize_prefix(custom_prefix)
        if prefix is None and card_type and card_type.card_prefix:
            prefix = card_type.card_prefix

        if custom_ttl_days is not None and custom_ttl_days < 0:
            raise ValueError("custom_ttl_invalid")
        if ttl_days is not None and ttl_days < 0:
            raise ValueError("ttl_invalid")

        if card_code:
            normalized_code = self._normalize_card_code(card_code)
            if self.get_license(normalized_code):
                raise ValueError("card_code_exists")
        else:
            normalized_code = None

        base_duration = custom_ttl_days
        if base_duration is None:
            if card_type and card_type.default_duration_days is not None:
                base_duration = card_type.default_duration_days
            else:
                base_duration = ttl_days

        now = datetime.now(timezone.utc)
        created: list[models.License] = []
        batch_code = secrets.token_hex(4).upper()

        created_by = None
        if self._actor:
            created_by = self._actor.name or (str(self._actor.id) if self._actor.id is not None else None)

        batch_metadata: dict[str, object] = {
            "type": card_type.code if card_type else None,
            "custom_prefix": prefix,
            "ttl_days": base_duration,
            "slot": slot.code,
            "quantity_requested": quantity,
        }

        batch = models.LicenseBatch(
            batch_code=batch_code,
            card_type=card_type,
            quantity=quantity,
            created_by=created_by,
            metadata_json=batch_metadata,
        )
        self.db.add(batch)
        self.db.flush()

        for index in range(quantity):
            if index == 0 and normalized_code:
                code = normalized_code
            else:
                attempt = self._generate_card_code(prefix)
                while self.get_license(attempt):
                    attempt = self._generate_card_code(prefix)
                code = attempt

            secret = secrets.token_urlsafe(32)
            expire_at = None
            if base_duration is not None and base_duration > 0:
                expire_at = now + timedelta(days=base_duration)

            license_obj = models.License(
                card_code=code,
                secret=secret,
                expire_at=expire_at,
                status=models.LicenseStatus.UNUSED.value,
                card_prefix=prefix,
                software_slot=slot,
                batch=batch,
            )

            if card_type:
                license_obj.card_type = card_type
                if custom_ttl_days is not None:
                    license_obj.custom_duration_days = custom_ttl_days
            elif ttl_days is not None:
                license_obj.custom_duration_days = ttl_days

            self.db.add(license_obj)
            created.append(license_obj)

        self.db.flush()

        for license_obj in created:
            meta = {
                "type": card_type.code if card_type else None,
                "custom_prefix": prefix,
                "ttl_days": base_duration,
                "batch_code": batch.batch_code,
                "batch_id": batch.id,
                "slot": slot.code,
            }
            self.log_event(license_obj, "create", f"License created: {json.dumps(meta, ensure_ascii=False)}")

        batch.quantity = len(created)
        self.db.commit()

        self.db.refresh(batch)
        for license_obj in created:
            self.db.refresh(license_obj)

        return created, batch

    def create_license(self, card_code: Optional[str], ttl_days: int, *, slot_code: Optional[str]) -> models.License:
        licenses, _ = self.create_licenses(
            card_code=card_code,
            ttl_days=ttl_days,
            quantity=1,
            slot_code=slot_code,
        )
        return licenses[0]

    def log_event(
        self,
        license_obj: models.License,
        action: str,
        message: Optional[str] = None,
        *,
        actor: Optional[AuditActor] = None,
        payload: Optional[dict[str, object]] = None,
        request_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        effective_actor = actor or self._actor

        self.audit.log_license_event(
            license_obj,
            action=action,
            actor=effective_actor,
            message=message,
            payload=payload,
            request_id=request_id,
            ip_address=ip_address,
        )

    def get_audit_logs(self, license_obj: models.License, limit: int = 50) -> list[models.AuditLog]:
        if license_obj.id is None:
            self.db.flush()

        return self.audit.list_logs_for_license(license_obj.id, limit=limit)

    def activate(self, request: ActivationRequest) -> tuple[Optional[str], Optional[datetime], str]:
        license_obj = self.get_license(request.card_code)
        if not license_obj:
            return None, None, "license_not_found"

        slot = license_obj.software_slot
        requested_slot_code = (request.slot_code or "").strip().lower() if getattr(request, "slot_code", None) else ""
        if slot:
            if not requested_slot_code:
                return None, None, "slot_code_required"
            if slot.code != requested_slot_code:
                return None, None, "slot_mismatch"
        else:
            return None, None, "license_slot_unset"

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

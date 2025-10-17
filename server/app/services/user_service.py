from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import models
from app.db.models import LicenseStatus
from app.services import security
from app.services.license_service import LicenseService


class UserService:
    def __init__(self, db: Session):
        self.db = db

    def register(self, username: str, password: str, card_code: str, slot_code: Optional[str]) -> models.User:
        username = (username or "").strip()
        card_code = (card_code or "").strip()
        normalized_slot = (slot_code or "").strip().lower()

        if len(username) < 3:
            raise ValueError("username_too_short")
        if len(password) < 8:
            raise ValueError("password_too_short")
        if not card_code:
            raise ValueError("card_code_required")
        if not normalized_slot:
            raise ValueError("slot_code_required")

        license_obj = self.db.scalar(select(models.License).where(models.License.card_code == card_code))
        if not license_obj:
            raise ValueError("license_not_found")

        slot = license_obj.software_slot
        if not slot:
            raise ValueError("license_slot_unset")
        if slot.code != normalized_slot:
            raise ValueError("slot_mismatch")

        now = datetime.now(timezone.utc)
        expire_at = license_obj.expire_at
        if expire_at and expire_at.tzinfo is None:
            expire_at = expire_at.replace(tzinfo=timezone.utc)
        if expire_at and expire_at < now:
            license_obj.status = LicenseStatus.EXPIRED.value
            LicenseService(self.db).log_event(
                license_obj,
                "license_expired",
                "Registration attempted on expired license",
            )
            self.db.commit()
            raise ValueError("license_expired")

        if license_obj.status == LicenseStatus.REVOKED.value:
            raise ValueError("license_revoked")
        if license_obj.user:
            raise ValueError("license_already_bound")

        password_hash = security.hash_password(password)

        user = models.User(
            username=username,
            password_hash=password_hash,
            license=license_obj,
        )
        self.db.add(user)

        license_obj.updated_at = now
        LicenseService(self.db).log_event(
            license_obj,
            "user_register",
            f"User {username} registered",
        )

        try:
            self.db.commit()
        except IntegrityError as err:
            self.db.rollback()
            message = str(err.orig).lower() if getattr(err, "orig", None) else str(err).lower()
            if "users.username" in message:
                raise ValueError("username_taken")
            if "users.license_id" in message or "license_id" in message:
                raise ValueError("license_already_bound")
            raise ValueError("registration_failed")

        self.db.refresh(user)
        return user

    def list_users(self, *, offset: int = 0, limit: int = 100, search: Optional[str] = None) -> List[models.User]:
        offset = max(offset, 0)
        limit = max(1, min(limit, 200))

        stmt = select(models.User).order_by(models.User.created_at.desc()).offset(offset).limit(limit)
        if search:
            pattern = f"%{search.strip()}%"
            stmt = stmt.where(models.User.username.ilike(pattern))

        return list(self.db.scalars(stmt).all())

    def get_user(self, user_id: int) -> Optional[models.User]:
        return self.db.get(models.User, user_id)

    def update_user(
        self,
        user_id: int,
        *,
        username: Optional[str] = None,
        password: Optional[str] = None,
        card_code: Optional[str] = None,
        slot_code: Optional[str] = None,
    ) -> models.User:
        user = self.db.get(models.User, user_id)
        if not user:
            raise ValueError("user_not_found")

        updated = False
        now = datetime.now(timezone.utc)
        license_service = LicenseService(self.db)

        normalized_slot = (slot_code or "").strip().lower() if slot_code else None

        if username is not None:
            new_username = username.strip()
            if len(new_username) < 3:
                raise ValueError("username_too_short")
            if new_username != user.username:
                user.username = new_username
                updated = True

        if password is not None:
            if len(password) < 8:
                raise ValueError("password_too_short")
            user.password_hash = security.hash_password(password)
            updated = True

        if card_code is not None:
            card_code = card_code.strip()
            if not card_code:
                raise ValueError("card_code_required")

            current_license = user.license
            if not current_license or current_license.card_code != card_code:
                new_license = self.db.scalar(select(models.License).where(models.License.card_code == card_code))
                if not new_license:
                    raise ValueError("license_not_found")
                if new_license.user and new_license.user.id != user.id:
                    raise ValueError("license_already_bound")
                if new_license.status == LicenseStatus.REVOKED.value:
                    raise ValueError("license_revoked")

                if not new_license.software_slot:
                    raise ValueError("license_slot_unset")
                target_slot_code = normalized_slot or (current_license.software_slot.code if current_license and current_license.software_slot else None)
                if not target_slot_code:
                    raise ValueError("slot_code_required")
                if new_license.software_slot.code != target_slot_code:
                    raise ValueError("slot_mismatch")

                if current_license and current_license.id != new_license.id:
                    current_license.user = None
                    current_license.bound_fingerprint = None
                    if current_license.status != LicenseStatus.REVOKED.value:
                        current_license.status = LicenseStatus.UNUSED.value
                    current_license.updated_at = now
                    license_service.log_event(current_license, "user_unbind", f"User {user.username} unbound")

                user.license = new_license
                new_license.status = LicenseStatus.ACTIVE.value
                new_license.updated_at = now
                license_service.log_event(new_license, "user_rebind", f"User {user.username} re-bound")
                updated = True
            else:
                # card code unchanged; ensure slot still matches request if provided
                if normalized_slot and current_license and current_license.software_slot:
                    if current_license.software_slot.code != normalized_slot:
                        raise ValueError("slot_mismatch")
                elif normalized_slot:
                    raise ValueError("license_slot_unset")
        elif normalized_slot:
            current_license = user.license
            if not current_license or not current_license.software_slot:
                raise ValueError("license_slot_unset")
            if current_license.software_slot.code != normalized_slot:
                raise ValueError("slot_mismatch")

        if not updated:
            return user

        try:
            self.db.commit()
        except IntegrityError as err:
            self.db.rollback()
            message = str(err.orig).lower() if getattr(err, "orig", None) else str(err).lower()
            if "users.username" in message:
                raise ValueError("username_taken")
            raise ValueError("user_update_failed")

        self.db.refresh(user)
        return user

    def delete_user(self, user_id: int) -> bool:
        user = self.db.get(models.User, user_id)
        if not user:
            return False

        license_service = LicenseService(self.db)
        license_obj = user.license
        username = user.username

        self.db.delete(user)

        if license_obj:
            license_obj.user = None
            if license_obj.status != LicenseStatus.REVOKED.value:
                license_obj.status = LicenseStatus.UNUSED.value
            license_obj.bound_fingerprint = None
            license_obj.updated_at = datetime.now(timezone.utc)
            license_service.log_event(license_obj, "user_delete", f"User {username} deleted")

        self.db.commit()
        return True

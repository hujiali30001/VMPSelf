from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import (
    SoftwarePackage,
    SoftwarePackageStatus,
    SoftwareSlot,
    SoftwareSlotStatus,
)


class SoftwareService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # Slots ---------------------------------------------------------------------
    def list_slots(self) -> List[SoftwareSlot]:
        stmt = select(SoftwareSlot).order_by(SoftwareSlot.created_at.desc())
        return list(self.db.scalars(stmt).all())

    def get_slot(self, slot_id: int) -> Optional[SoftwareSlot]:
        return self.db.get(SoftwareSlot, slot_id)

    def create_slot(
        self,
        *,
        code: str,
        name: str,
        product_line: Optional[str] = None,
        channel: Optional[str] = None,
        gray_ratio: Optional[int] = None,
        notes: Optional[str] = None,
    ) -> SoftwareSlot:
        code = (code or "").strip().lower()
        name = (name or "").strip()
        product_line = (product_line or "").strip() or None
        channel = (channel or "").strip() or None
        notes = (notes or "").strip() or None

        if len(code) < 2:
            raise ValueError("code_too_short")
        if len(name) < 3:
            raise ValueError("name_too_short")
        if gray_ratio is not None and (gray_ratio < 0 or gray_ratio > 100):
            raise ValueError("gray_ratio_invalid")

        existing = self.db.scalar(select(SoftwareSlot).where(SoftwareSlot.code == code))
        if existing:
            raise ValueError("slot_code_exists")

        slot = SoftwareSlot(
            code=code,
            name=name,
            product_line=product_line,
            channel=channel,
            gray_ratio=gray_ratio,
            notes=notes,
        )
        self.db.add(slot)
        self.db.commit()
        self.db.refresh(slot)
        return slot

    def set_slot_status(self, slot_id: int, status: SoftwareSlotStatus) -> SoftwareSlot:
        slot = self.db.get(SoftwareSlot, slot_id)
        if not slot:
            raise ValueError("slot_not_found")
        slot.status = status.value
        slot.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(slot)
        return slot

    def set_slot_current_package(self, slot: SoftwareSlot, package: Optional[SoftwarePackage]) -> None:
        slot.current_package = package
        slot.updated_at = datetime.now(timezone.utc)
        self.db.flush()

    # Packages ------------------------------------------------------------------
    def list_packages(self, slot_id: int, limit: int = 20) -> List[SoftwarePackage]:
        stmt = (
            select(SoftwarePackage)
            .where(SoftwarePackage.slot_id == slot_id)
            .order_by(SoftwarePackage.created_at.desc())
            .limit(max(1, min(limit, 100)))
        )
        return list(self.db.scalars(stmt).all())

    def create_package(
        self,
        *,
        slot_id: int,
        version: str,
        file_url: Optional[str] = None,
        checksum: Optional[str] = None,
        release_notes: Optional[str] = None,
        promote: bool = False,
        mark_critical: bool = False,
    ) -> SoftwarePackage:
        slot = self.db.get(SoftwareSlot, slot_id)
        if not slot:
            raise ValueError("slot_not_found")

        version = (version or "").strip()
        if len(version) < 1:
            raise ValueError("version_required")

        file_url = (file_url or "").strip() or None
        checksum = (checksum or "").strip() or None
        release_notes = (release_notes or "").strip() or None

        existing = self.db.scalar(
            select(SoftwarePackage).where(
                SoftwarePackage.slot_id == slot_id,
                SoftwarePackage.version == version,
            )
        )
        if existing:
            raise ValueError("version_exists")

        package = SoftwarePackage(
            slot=slot,
            version=version,
            file_url=file_url,
            checksum=checksum,
            release_notes=release_notes,
            is_critical=mark_critical,
            status=SoftwarePackageStatus.DRAFT.value,
        )
        self.db.add(package)
        self.db.flush()

        now = datetime.now(timezone.utc)
        if promote:
            self._promote_package(slot, package, promoted_at=now)
        else:
            package.status = SoftwarePackageStatus.DRAFT.value

        self.db.commit()
        self.db.refresh(package)
        return package

    def promote_package(self, package_id: int) -> SoftwarePackage:
        package = self.db.get(SoftwarePackage, package_id)
        if not package:
            raise ValueError("package_not_found")
        slot = package.slot
        now = datetime.now(timezone.utc)
        self._promote_package(slot, package, promoted_at=now)
        self.db.commit()
        self.db.refresh(package)
        return package

    def retire_package(self, package_id: int) -> SoftwarePackage:
        package = self.db.get(SoftwarePackage, package_id)
        if not package:
            raise ValueError("package_not_found")
        package.status = SoftwarePackageStatus.RETIRED.value
        package.promoted_at = None
        slot = package.slot
        if slot.current_package_id == package.id:
            slot.current_package = None
        self.db.commit()
        self.db.refresh(package)
        return package

    def _promote_package(
        self,
        slot: SoftwareSlot,
        package: SoftwarePackage,
        *,
        promoted_at: datetime,
    ) -> None:
        # retire existing active package
        if slot.current_package:
            slot.current_package.status = SoftwarePackageStatus.RETIRED.value
            slot.current_package.promoted_at = None

        package.status = SoftwarePackageStatus.ACTIVE.value
        package.promoted_at = promoted_at
        self.set_slot_current_package(slot, package)

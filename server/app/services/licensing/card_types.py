from __future__ import annotations

import re
from typing import Iterable, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import models
from .licenses import LicenseService


class LicenseCardTypeService:
    CODE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{1,31}$")

    def __init__(self, db: Session):
        self.db = db

    def list_types(self, *, include_inactive: bool = True) -> list[models.LicenseCardType]:
        stmt = select(models.LicenseCardType).order_by(
            models.LicenseCardType.sort_order,
            models.LicenseCardType.id,
        )
        if not include_inactive:
            stmt = stmt.where(models.LicenseCardType.is_active.is_(True))
        return list(self.db.scalars(stmt).all())

    def get_by_id(self, type_id: int) -> Optional[models.LicenseCardType]:
        return self.db.get(models.LicenseCardType, type_id)

    def create_type(
        self,
        *,
        code: str,
        display_name: str,
        default_duration_days: Optional[int] = None,
        card_prefix: Optional[str] = None,
        description: Optional[str] = None,
        color: Optional[str] = None,
        sort_order: Optional[int] = None,
        is_active: bool = True,
    ) -> models.LicenseCardType:
        normalized_code = self._normalize_code(code)
        if self._exists(code=normalized_code):
            raise ValueError("card_type_exists")

        prefix = LicenseService._normalize_prefix(card_prefix)
        duration = self._normalize_duration(default_duration_days)
        color_code = self._normalize_color(color)
        order = self._normalize_sort_order(sort_order)

        card_type = models.LicenseCardType(
            code=normalized_code,
            display_name=display_name.strip(),
            default_duration_days=duration,
            card_prefix=prefix,
            description=(description or "").strip() or None,
            color=color_code,
            sort_order=order,
            is_active=is_active,
        )
        self.db.add(card_type)
        self.db.commit()
        self.db.refresh(card_type)
        return card_type

    def update_type(
        self,
        type_id: int,
        *,
        display_name: Optional[str] = None,
        default_duration_days: Optional[int] = None,
        card_prefix: Optional[str] = None,
        description: Optional[str] = None,
        color: Optional[str] = None,
        sort_order: Optional[int] = None,
        is_active: Optional[bool] = None,
    ) -> models.LicenseCardType:
        card_type = self.get_by_id(type_id)
        if not card_type:
            raise ValueError("card_type_not_found")

        changed = False

        if display_name is not None:
            trimmed = display_name.strip()
            if not trimmed:
                raise ValueError("display_name_blank")
            card_type.display_name = trimmed
            changed = True

        if default_duration_days is not None:
            card_type.default_duration_days = self._normalize_duration(default_duration_days)
            changed = True

        if card_prefix is not None:
            card_type.card_prefix = LicenseService._normalize_prefix(card_prefix)
            changed = True

        if description is not None:
            card_type.description = description.strip() or None
            changed = True

        if color is not None:
            card_type.color = self._normalize_color(color)
            changed = True

        if sort_order is not None:
            card_type.sort_order = self._normalize_sort_order(sort_order)
            changed = True

        if is_active is not None:
            card_type.is_active = is_active
            changed = True

        if not changed:
            return card_type

        self.db.commit()
        self.db.refresh(card_type)
        return card_type

    def delete_type(self, type_id: int) -> bool:
        card_type = self.get_by_id(type_id)
        if not card_type:
            return False

        in_use = self.db.scalar(
            select(func.count()).select_from(models.License).where(models.License.card_type_id == type_id)
        )
        if in_use:
            raise ValueError("card_type_in_use")

        self.db.delete(card_type)
        self.db.commit()
        return True

    def _exists(self, *, code: Optional[str] = None) -> bool:
        stmt = select(func.count()).select_from(models.LicenseCardType)
        if code:
            stmt = stmt.where(models.LicenseCardType.code == code)
        return (self.db.scalar(stmt) or 0) > 0

    def _normalize_code(self, code: str) -> str:
        slug = code.strip().lower()
        if not slug:
            raise ValueError("code_blank")
        if not self.CODE_PATTERN.match(slug):
            raise ValueError("code_invalid")
        return slug

    def _normalize_duration(self, value: Optional[int]) -> Optional[int]:
        if value is None:
            return None
        if value < 0:
            raise ValueError("duration_invalid")
        if value > 3650:
            raise ValueError("duration_too_large")
        return value

    def _normalize_sort_order(self, value: Optional[int]) -> int:
        if value is not None:
            return max(0, min(value, 1000))
        max_existing = self.db.scalar(select(func.max(models.LicenseCardType.sort_order)))
        if max_existing is None:
            return 10
        return int(max_existing) + 10

    def _normalize_color(self, color: Optional[str]) -> Optional[str]:
        if color is None:
            return None
        trimmed = color.strip()
        if not trimmed:
            return None
        if not re.fullmatch(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$", trimmed):
            raise ValueError("color_invalid")
        return trimmed.lower()

    def ensure_codes(self, codes: Iterable[str]) -> dict[str, models.LicenseCardType]:
        if not codes:
            return {}
        stmt = select(models.LicenseCardType).where(models.LicenseCardType.code.in_(list(codes)))
        return {card_type.code: card_type for card_type in self.db.scalars(stmt).all()}

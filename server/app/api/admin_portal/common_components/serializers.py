from __future__ import annotations

from typing import Any, Optional

from app.db import License, models


def _serialize_user(user: Optional[models.User]) -> Optional[dict[str, Any]]:
    if not user:
        return None
    license_obj = user.license
    return {
        "id": user.id,
        "username": user.username,
        "created_at": user.created_at,
        "card_code": license_obj.card_code if license_obj else None,
        "license_status": license_obj.status if license_obj else None,
        "slot_code": license_obj.software_slot.code if (license_obj and license_obj.software_slot) else None,
    }


def _serialize_card_type(card_type: Optional[models.LicenseCardType]) -> Optional[dict[str, Any]]:
    if not card_type:
        return None
    return {
        "id": card_type.id,
        "code": card_type.code,
        "display_name": card_type.display_name,
        "default_duration_days": card_type.default_duration_days,
        "card_prefix": card_type.card_prefix,
        "description": card_type.description,
        "color": card_type.color,
        "is_active": card_type.is_active,
        "sort_order": card_type.sort_order,
        "created_at": card_type.created_at,
        "updated_at": card_type.updated_at,
    }


def _serialize_batch(batch: Optional[models.LicenseBatch]) -> Optional[dict[str, Any]]:
    if not batch:
        return None
    return {
        "id": batch.id,
        "batch_code": batch.batch_code,
        "quantity": batch.quantity,
        "created_at": batch.created_at,
        "created_by": batch.created_by,
        "type_code": batch.card_type.code if batch.card_type else None,
        "metadata": getattr(batch, "metadata_json", None),
    }


def _serialize_license(license_obj: License) -> dict[str, Any]:
    return {
        "id": license_obj.id,
        "card_code": license_obj.card_code,
        "secret": license_obj.secret,
        "status": license_obj.status,
        "bound_fingerprint": license_obj.bound_fingerprint,
        "expire_at": license_obj.expire_at,
        "created_at": license_obj.created_at,
        "updated_at": license_obj.updated_at,
        "user": _serialize_user(license_obj.user),
        "card_type": _serialize_card_type(getattr(license_obj, "card_type", None)),
        "card_prefix": license_obj.card_prefix,
        "custom_duration_days": license_obj.custom_duration_days,
        "slot_code": license_obj.software_slot.code if license_obj.software_slot else None,
        "batch_id": license_obj.batch.id if license_obj.batch else None,
        "batch_code": license_obj.batch.batch_code if license_obj.batch else None,
        "notes": license_obj.notes,
        "batch": _serialize_batch(license_obj.batch) if license_obj.batch else None,
    }


__all__ = [
    "_serialize_user",
    "_serialize_card_type",
    "_serialize_batch",
    "_serialize_license",
]

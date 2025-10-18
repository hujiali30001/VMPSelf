from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.admin_portal.common import AdminPrincipal, _serialize_card_type, require_permission
from app.api.deps import get_db
from app.schemas import (
    LicenseCardTypeCreateRequest,
    LicenseCardTypeListResponse,
    LicenseCardTypeResponse,
    LicenseCardTypeUpdateRequest,
)
from app.services.card_type_service import LicenseCardTypeService

router = APIRouter(prefix="/license-types")


@router.get("/", response_model=LicenseCardTypeListResponse)
def api_list_license_types(
    include_inactive: bool = True,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("license-types", "view")),
):
    service = LicenseCardTypeService(db)
    items = service.list_types(include_inactive=include_inactive)
    return {
        "items": [_serialize_card_type(item) for item in items if item],
        "total": len(items),
    }


@router.post("/", response_model=LicenseCardTypeResponse, status_code=201)
def api_create_license_type(
    payload: LicenseCardTypeCreateRequest,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("license-types", "manage")),
):
    service = LicenseCardTypeService(db)
    try:
        card_type = service.create_type(**payload.dict())
    except ValueError as exc:
        message = str(exc)
        if message in {
            "card_type_exists",
            "code_blank",
            "code_invalid",
            "duration_invalid",
            "duration_too_large",
            "prefix_too_long",
            "prefix_invalid",
            "color_invalid",
        }:
            raise HTTPException(status_code=400, detail=message)
        raise
    serialized = _serialize_card_type(card_type)
    assert serialized is not None
    return serialized


@router.patch("/{type_id}", response_model=LicenseCardTypeResponse)
def api_update_license_type(
    type_id: int,
    payload: LicenseCardTypeUpdateRequest,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("license-types", "manage")),
):
    updates = payload.dict(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="no_fields_provided")

    service = LicenseCardTypeService(db)
    try:
        card_type = service.update_type(type_id, **updates)
    except ValueError as exc:
        message = str(exc)
        if message in {
            "card_type_not_found",
        }:
            raise HTTPException(status_code=404, detail=message)
        if message in {
            "display_name_blank",
            "duration_invalid",
            "duration_too_large",
            "prefix_too_long",
            "prefix_invalid",
            "color_invalid",
        }:
            raise HTTPException(status_code=400, detail=message)
        raise

    serialized = _serialize_card_type(card_type)
    assert serialized is not None
    return serialized


@router.delete("/{type_id}", status_code=204)
def api_delete_license_type(
    type_id: int,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("license-types", "manage")),
):
    service = LicenseCardTypeService(db)
    try:
        service.delete_type(type_id)
    except ValueError as exc:
        if str(exc) == "card_type_not_found":
            raise HTTPException(status_code=404, detail="card_type_not_found")
        raise
    return None

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.admin_portal.common import (
    AdminPrincipal,
    _license_service,
    _serialize_batch,
    _serialize_license,
    require_permission,
)
from app.api.deps import get_db
from app.db import License, models
from app.schemas import (
    LicenseAdminResponse,
    LicenseBatchCreateResponse,
    LicenseBatchDetailResponse,
    LicenseBatchListResponse,
    LicenseCreateRequest,
    LicenseListResponse,
    LicenseUpdateRequest,
)
from app.services.license_service import LicenseService

router = APIRouter(prefix="/licenses")


@router.get("/", response_model=LicenseListResponse)
def api_list_licenses(
    offset: int = Query(0, ge=0, le=10_000),
    limit: int = Query(50, ge=1, le=500),
    status: str = Query("all"),
    search: Optional[str] = Query(None),
    type_code: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("licenses", "view")),
):
    status_filter = status.strip().lower() if status else "all"
    search_query = search.strip() if search else None
    type_filter = type_code.strip().lower() if type_code else None

    service = LicenseService(db)
    items = service.list_licenses(
        status=status_filter,
        search=search_query,
        type_code=type_filter,
        offset=offset,
        limit=limit,
    )

    total_stmt = select(func.count()).select_from(License)
    if status_filter and status_filter != "all":
        total_stmt = total_stmt.where(License.status == status_filter)
    if search_query:
        total_stmt = total_stmt.where(License.card_code.ilike(f"%{search_query}%"))
    if type_filter:
        total_stmt = (
            total_stmt.join_from(
                License,
                models.LicenseCardType,
                License.card_type_id == models.LicenseCardType.id,
            ).where(models.LicenseCardType.code == type_filter)
        )
    total = db.scalar(total_stmt) or 0

    return {
        "items": [_serialize_license(license_obj) for license_obj in items],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.post("/", response_model=LicenseBatchCreateResponse, status_code=201)
def api_create_license(
    payload: LicenseCreateRequest,
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("licenses", "manage")),
):
    service = _license_service(db, principal)
    try:
        licenses, batch = service.create_licenses(
            type_code=payload.type_code,
            card_code=payload.card_code,
            quantity=payload.quantity,
            custom_prefix=payload.custom_prefix,
            ttl_days=payload.ttl_days,
            custom_ttl_days=payload.custom_ttl_days,
            slot_code=payload.slot_code,
        )
    except ValueError as exc:
        message = str(exc)
        if message in {
            "card_type_not_found",
            "card_type_disabled",
            "card_code_exists",
            "card_code_blank",
            "card_code_too_long",
            "card_code_requires_single_quantity",
            "quantity_invalid",
            "quantity_too_large",
            "custom_ttl_invalid",
            "ttl_invalid",
            "prefix_invalid",
            "prefix_too_long",
            "slot_code_required",
            "slot_not_found",
        }:
            raise HTTPException(status_code=400, detail=message)
        raise
    except IntegrityError:
        raise HTTPException(status_code=400, detail="card_code_exists")

    return {
        "items": [_serialize_license(obj) for obj in licenses],
        "batch": _serialize_batch(batch),
        "quantity": len(licenses),
    }


@router.get("/batches", response_model=LicenseBatchListResponse)
def api_list_license_batches(
    offset: int = Query(0, ge=0, le=10_000),
    limit: int = Query(20, ge=1, le=200),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("licenses", "view")),
):
    service = LicenseService(db)
    items = service.list_batches(offset=offset, limit=limit)
    total = db.scalar(select(func.count()).select_from(models.LicenseBatch)) or 0
    return {
        "items": [_serialize_batch(batch) for batch in items if batch],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.get("/batches/{batch_id}", response_model=LicenseBatchDetailResponse)
def api_get_license_batch(
    batch_id: int,
    include_licenses: bool = Query(True),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("licenses", "view")),
):
    service = LicenseService(db)
    batch = service.get_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="batch_not_found")
    licenses = batch.licenses if include_licenses else []
    return {
        "batch": _serialize_batch(batch),
        "licenses": [_serialize_license(license_obj) for license_obj in licenses],
    }


@router.get("/batches/by-code/{batch_code}", response_model=LicenseBatchDetailResponse)
def api_get_license_batch_by_code(
    batch_code: str,
    include_licenses: bool = Query(True),
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("licenses", "view")),
):
    service = LicenseService(db)
    batch = service.get_batch_by_code(batch_code)
    if not batch:
        raise HTTPException(status_code=404, detail="batch_not_found")
    licenses = batch.licenses if include_licenses else []
    return {
        "batch": _serialize_batch(batch),
        "licenses": [_serialize_license(license_obj) for license_obj in licenses],
    }


@router.get("/{card_code}", response_model=LicenseAdminResponse)
def api_get_license(
    card_code: str,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("licenses", "view")),
):
    license_obj = LicenseService(db).get_license(card_code)
    if not license_obj:
        raise HTTPException(status_code=404, detail="license_not_found")
    return _serialize_license(license_obj)


@router.patch("/{card_code}", response_model=LicenseAdminResponse)
def api_update_license(
    card_code: str,
    payload: LicenseUpdateRequest,
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("licenses", "manage")),
):
    if payload.expire_at is None and payload.status is None and payload.bound_fingerprint is None:
        raise HTTPException(status_code=400, detail="no_fields_provided")

    service = _license_service(db, principal)
    try:
        license_obj = service.update_license(
            card_code,
            expire_at=payload.expire_at,
            status=payload.status,
            bound_fingerprint=payload.bound_fingerprint,
        )
    except ValueError as exc:
        message = str(exc)
        if message in {"license_not_found", "invalid_expiry", "invalid_status"}:
            status_code = 404 if message == "license_not_found" else 400
            raise HTTPException(status_code=status_code, detail=message)
        raise

    return _serialize_license(license_obj)


@router.delete("/{card_code}", status_code=204)
def api_delete_license(
    card_code: str,
    force: bool = Query(False),
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("licenses", "manage")),
):
    service = _license_service(db, principal)
    try:
        success = service.delete_license(card_code, force=force)
    except ValueError as exc:
        message = str(exc)
        if message == "license_not_found":
            raise HTTPException(status_code=404, detail="license_not_found")
        if message == "license_active":
            raise HTTPException(status_code=400, detail="license_active")
        raise
    if not success:
        raise HTTPException(status_code=400, detail="license_active")
    return Response(status_code=204)

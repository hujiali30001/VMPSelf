from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.settings import get_settings
from app.schemas import (
    ActivationRequest,
    ActivationResponse,
    HeartbeatRequest,
    LicenseClientConfigResponse,
    LicenseDetailResponse,
    LicenseResetRequest,
    OfflineLicenseRequest,
    OfflineLicenseResponse,
    RevokeRequest,
)
from app.services.licensing import LicenseService
from app.services.security import issue_token, sign_message, verify_signature

router = APIRouter(prefix="/license", tags=["licenses"])
settings = get_settings()


@router.post("/activate", response_model=ActivationResponse)
def activate_license(payload: ActivationRequest, db: Session = Depends(get_db)):
    service = LicenseService(db)
    token, expires_at, status = service.activate(payload)
    if not token:
        raise HTTPException(status_code=400, detail=status)

    return ActivationResponse(
        token=token,
        expires_at=expires_at,
        heartbeat_interval_seconds=settings.heartbeat_interval_seconds,
    )


@router.post("/heartbeat")
def heartbeat(payload: HeartbeatRequest, db: Session = Depends(get_db)):
    service = LicenseService(db)
    if not service.heartbeat(payload):
        raise HTTPException(status_code=401, detail="invalid_token")
    return {"status": "ok"}


@router.post("/offline", response_model=OfflineLicenseResponse)
def generate_offline(payload: OfflineLicenseRequest, db: Session = Depends(get_db)):
    service = LicenseService(db)
    license_obj = service.get_license(payload.card_code)
    if not license_obj:
        raise HTTPException(status_code=404, detail="license_not_found")

    if not verify_signature(
        payload.card_code,
        payload.fingerprint,
        int(payload.expires_at.timestamp()),
        payload.signature,
        shared_secret=license_obj.secret,
    ):
        raise HTTPException(status_code=400, detail="invalid_signature")

    token, _ = issue_token(payload.card_code, payload.fingerprint)
    expires = payload.expires_at.replace(tzinfo=timezone.utc)
    blob = {
        "card_code": payload.card_code,
        "fingerprint": payload.fingerprint,
        "token": token,
        "expires_at": expires.isoformat(),
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }

    license_blob = json.dumps(blob, separators=(",", ":"))
    signature = sign_message(license_blob, shared_secret=license_obj.secret)
    service.log_event(license_obj, "offline_issue", "Offline license generated")
    db.commit()

    return OfflineLicenseResponse(license_blob=license_blob, signature=signature)


@router.post("/revoke")
def revoke(payload: RevokeRequest, db: Session = Depends(get_db)):
    service = LicenseService(db)
    if not service.revoke(payload.card_code):
        raise HTTPException(status_code=404, detail="license_not_found")


@router.post("/reset")
def reset_license(payload: LicenseResetRequest, db: Session = Depends(get_db)):
    service = LicenseService(db)
    if not service.reset_license(payload.card_code):
        raise HTTPException(status_code=404, detail="license_not_found")
    return {"status": "ok"}


@router.get("/config", response_model=LicenseClientConfigResponse)
def get_license_config() -> LicenseClientConfigResponse:
    return LicenseClientConfigResponse(
        heartbeat_interval_seconds=settings.heartbeat_interval_seconds,
        token_ttl_minutes=settings.token_ttl_minutes,
        offline_ttl_minutes=settings.allow_offline_minutes,
    )


@router.get("/detail", response_model=LicenseDetailResponse)
def get_license_detail(
    card_code: str = Query(..., max_length=64),
    db: Session = Depends(get_db),
) -> LicenseDetailResponse:
    service = LicenseService(db)
    license_obj = service.get_license(card_code.strip())
    if not license_obj:
        raise HTTPException(status_code=404, detail="license_not_found")

    slot_code = license_obj.software_slot.code if license_obj.software_slot else None
    card_type = license_obj.card_type.code if license_obj.card_type else None

    return LicenseDetailResponse(
        card_code=license_obj.card_code,
        status=license_obj.status,
        bound_fingerprint=license_obj.bound_fingerprint,
        expire_at=license_obj.expire_at,
        card_type=card_type,
        slot_code=slot_code,
        created_at=license_obj.created_at,
        updated_at=license_obj.updated_at,
    )
    return {"status": "revoked"}

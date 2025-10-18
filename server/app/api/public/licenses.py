from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.settings import get_settings
from app.schemas import (
    ActivationRequest,
    ActivationResponse,
    HeartbeatRequest,
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
    return {"status": "revoked"}

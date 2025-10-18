from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.schemas import UserRegisterRequest, UserRegisterResponse
from app.services.user_service import UserService

router = APIRouter(prefix="/users", tags=["users"])


@router.post("/register", response_model=UserRegisterResponse, status_code=201)
def register_user(payload: UserRegisterRequest, db: Session = Depends(get_db)):
    service = UserService(db)
    try:
        user = service.register(payload.username, payload.password, payload.card_code, payload.slot_code)
    except ValueError as exc:
        message = str(exc)
        if message == "license_not_found":
            raise HTTPException(status_code=404, detail=message)
        if message in {
            "username_too_short",
            "password_too_short",
            "card_code_required",
            "license_revoked",
            "license_already_bound",
            "license_expired",
            "username_taken",
            "registration_failed",
            "slot_code_required",
            "slot_mismatch",
            "license_slot_unset",
            "slot_not_found",
        }:
            raise HTTPException(status_code=400, detail=message)
        raise

    license_obj = user.license
    return UserRegisterResponse(
        user_id=user.id,
        username=user.username,
        card_code=license_obj.card_code,
        license_status=license_obj.status,
        message="registered",
        slot_code=license_obj.software_slot.code if license_obj.software_slot else None,
    )

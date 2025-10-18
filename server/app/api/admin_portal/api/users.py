from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.admin_portal.common import (
    AdminPrincipal,
    _build_audit_actor,
    _serialize_user,
    require_permission,
)
from app.api.deps import get_db
from app.schemas import UserDetailResponse, UserListResponse, UserUpdateRequest
from app.services.user_service import UserService
from app.db import models

router = APIRouter(prefix="/users")


@router.get("/", response_model=UserListResponse)
def api_list_users(
    offset: int = 0,
    limit: int = 50,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("users", "view")),
):
    offset = max(offset, 0)
    limit = max(1, min(limit, 200))
    search_query = search.strip() if search else None

    service = UserService(db)
    items = service.list_users(offset=offset, limit=limit, search=search_query)

    total_stmt = select(func.count()).select_from(models.User)
    if search_query:
        total_stmt = total_stmt.where(models.User.username.ilike(f"%{search_query}%"))
    total = db.scalar(total_stmt) or 0

    return {
        "items": [_serialize_user(user) for user in items],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.get("/{user_id}", response_model=UserDetailResponse)
def api_get_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: AdminPrincipal = Depends(require_permission("users", "view")),
):
    user = UserService(db).get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user_not_found")
    serialized = _serialize_user(user)
    assert serialized is not None
    return serialized


@router.patch("/{user_id}", response_model=UserDetailResponse)
def api_update_user(
    user_id: int,
    payload: UserUpdateRequest,
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("users", "manage")),
):
    if (
        payload.username is None
        and payload.password is None
        and payload.card_code is None
        and payload.slot_code is None
    ):
        raise HTTPException(status_code=400, detail="no_fields_provided")

    service = UserService(db, actor=_build_audit_actor(principal))
    try:
        user = service.update_user(
            user_id,
            username=payload.username,
            password=payload.password,
            card_code=payload.card_code,
            slot_code=payload.slot_code,
        )
    except ValueError as exc:
        message = str(exc)
        if message in {
            "user_not_found",
            "username_too_short",
            "password_too_short",
            "card_code_required",
            "license_not_found",
            "license_already_bound",
            "license_revoked",
            "username_taken",
            "user_update_failed",
            "slot_code_required",
            "slot_not_found",
            "slot_mismatch",
            "license_slot_unset",
        }:
            status_code = 404 if message == "user_not_found" else 400
            raise HTTPException(status_code=status_code, detail=message)
        raise

    serialized = _serialize_user(user)
    assert serialized is not None
    return serialized


@router.delete("/{user_id}", status_code=204)
def api_delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    principal: AdminPrincipal = Depends(require_permission("users", "manage")),
):
    if not UserService(db, actor=_build_audit_actor(principal)).delete_user(user_id):
        raise HTTPException(status_code=404, detail="user_not_found")
    return Response(status_code=204)

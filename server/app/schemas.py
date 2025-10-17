from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class LicenseCardTypeResponse(BaseModel):
    id: int
    code: str = Field(..., max_length=32)
    display_name: str = Field(..., max_length=64)
    default_duration_days: Optional[int] = None
    card_prefix: Optional[str] = Field(None, max_length=16)
    color: Optional[str] = Field(None, max_length=16)
    description: Optional[str] = None
    is_active: bool
    sort_order: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class LicenseCardTypeCreateRequest(BaseModel):
    code: str = Field(..., max_length=32)
    display_name: str = Field(..., max_length=64)
    default_duration_days: Optional[int] = Field(None, ge=0, le=3650)
    card_prefix: Optional[str] = Field(None, max_length=16)
    description: Optional[str] = Field(None, max_length=500)
    color: Optional[str] = Field(None, max_length=16)
    sort_order: Optional[int] = Field(None, ge=0, le=1000)
    is_active: bool = True


class LicenseCardTypeUpdateRequest(BaseModel):
    display_name: Optional[str] = Field(None, max_length=64)
    default_duration_days: Optional[int] = Field(None, ge=0, le=3650)
    card_prefix: Optional[str] = Field(None, max_length=16)
    description: Optional[str] = Field(None, max_length=500)
    color: Optional[str] = Field(None, max_length=16)
    sort_order: Optional[int] = Field(None, ge=0, le=1000)
    is_active: Optional[bool] = None


class LicenseCardTypeListResponse(BaseModel):
    items: List[LicenseCardTypeResponse]
    total: int


class ActivationRequest(BaseModel):
    card_code: str
    fingerprint: str
    signature: str
    timestamp: int
    slot_code: str = Field(..., min_length=2, max_length=64)


class ActivationResponse(BaseModel):
    token: str
    expires_at: datetime
    heartbeat_interval_seconds: int


class HeartbeatRequest(BaseModel):
    token: str
    fingerprint: str
    signature: str
    timestamp: int


class OfflineLicenseRequest(BaseModel):
    card_code: str
    fingerprint: str
    expires_at: datetime
    signature: str


class OfflineLicenseResponse(BaseModel):
    license_blob: str
    signature: str


class PingResponse(BaseModel):
    message: str
    server_time: datetime


class RevokeRequest(BaseModel):
    card_code: str


class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8, max_length=128)
    card_code: str = Field(..., max_length=64)
    slot_code: str = Field(..., min_length=2, max_length=64)


class UserRegisterResponse(BaseModel):
    user_id: int
    username: str
    card_code: str
    license_status: str
    message: str
    slot_code: Optional[str]

    class Config:
        orm_mode = True


class UserDetailResponse(BaseModel):
    id: int
    username: str
    created_at: datetime
    card_code: Optional[str]
    license_status: Optional[str]
    slot_code: Optional[str]

    class Config:
        orm_mode = True


class UserListResponse(BaseModel):
    items: List[UserDetailResponse]
    total: int
    offset: int
    limit: int


class UserUpdateRequest(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=64)
    password: Optional[str] = Field(None, min_length=8, max_length=128)
    card_code: Optional[str] = Field(None, max_length=64)
    slot_code: Optional[str] = Field(None, min_length=2, max_length=64)


class LicenseCreateRequest(BaseModel):
    card_code: Optional[str] = Field(None, max_length=64)
    ttl_days: Optional[int] = Field(30, ge=0, le=3650)
    type_code: Optional[str] = Field(None, max_length=32)
    quantity: int = Field(1, ge=1, le=500)
    custom_prefix: Optional[str] = Field(None, max_length=16)
    custom_ttl_days: Optional[int] = Field(None, ge=0, le=3650)
    slot_code: str = Field(..., min_length=2, max_length=64)


class LicenseUpdateRequest(BaseModel):
    expire_at: Optional[datetime] = None
    status: Optional[str] = Field(None, max_length=16)
    bound_fingerprint: Optional[str] = Field(None, max_length=128)


class LicenseAdminResponse(BaseModel):
    id: int
    card_code: str
    secret: str
    status: str
    bound_fingerprint: Optional[str]
    expire_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    user: Optional[UserDetailResponse]
    card_type: Optional[LicenseCardTypeResponse]
    card_prefix: Optional[str]
    custom_duration_days: Optional[int]
    slot_code: Optional[str]

    class Config:
        orm_mode = True


class LicenseListResponse(BaseModel):
    items: List[LicenseAdminResponse]
    total: int
    offset: int
    limit: int


class LicenseBatchCreateResponse(BaseModel):
    items: List[LicenseAdminResponse]
    batch_id: str
    quantity: int

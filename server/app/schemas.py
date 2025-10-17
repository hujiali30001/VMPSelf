from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class LicenseBase(BaseModel):
    card_code: str = Field(..., max_length=64)
    secret: str = Field(..., max_length=128)
    expire_at: Optional[datetime] = None


class LicenseCreate(LicenseBase):
    pass


class LicenseResponse(LicenseBase):
    id: int
    status: str
    bound_fingerprint: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class ActivationRequest(BaseModel):
    card_code: str
    fingerprint: str
    signature: str
    timestamp: int


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


class UserRegisterResponse(BaseModel):
    user_id: int
    username: str
    card_code: str
    license_status: str
    message: str

    class Config:
        orm_mode = True


class UserDetailResponse(BaseModel):
    id: int
    username: str
    created_at: datetime
    card_code: Optional[str]
    license_status: Optional[str]

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


class LicenseCreateRequest(BaseModel):
    card_code: Optional[str] = Field(None, max_length=64)
    ttl_days: int = Field(30, ge=0, le=3650)


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

    class Config:
        orm_mode = True


class LicenseListResponse(BaseModel):
    items: List[LicenseAdminResponse]
    total: int
    offset: int
    limit: int

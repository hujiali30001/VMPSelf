from __future__ import annotations

from datetime import datetime
from typing import Any, List, Optional

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
    metadata: Optional[dict[str, Any]] = None
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
    metadata: Optional[dict[str, Any]] = None


class LicenseCardTypeUpdateRequest(BaseModel):
    display_name: Optional[str] = Field(None, max_length=64)
    default_duration_days: Optional[int] = Field(None, ge=0, le=3650)
    card_prefix: Optional[str] = Field(None, max_length=16)
    description: Optional[str] = Field(None, max_length=500)
    color: Optional[str] = Field(None, max_length=16)
    sort_order: Optional[int] = Field(None, ge=0, le=1000)
    is_active: Optional[bool] = None
    metadata: Optional[dict[str, Any]] = None


class LicenseCardTypeListResponse(BaseModel):
    items: List[LicenseCardTypeResponse]
    total: int


class ActivationRequest(BaseModel):
    card_code: str
    fingerprint: str
    signature: str
    timestamp: int
    slot_code: str = Field(..., min_length=2, max_length=64)
    use_slot_secret: bool = False


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


class LicenseResetRequest(BaseModel):
    card_code: str = Field(..., max_length=64)


class LicenseClientConfigResponse(BaseModel):
    heartbeat_interval_seconds: int
    token_ttl_minutes: int
    offline_ttl_minutes: int


class LicenseDetailResponse(BaseModel):
    card_code: str
    status: str
    bound_fingerprint: Optional[str]
    expire_at: Optional[datetime]
    card_type: Optional[str]
    slot_code: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


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
    batch_id: Optional[int]
    batch_code: Optional[str]
    notes: Optional[str]

    class Config:
        orm_mode = True


class LicenseListResponse(BaseModel):
    items: List[LicenseAdminResponse]
    total: int
    offset: int
    limit: int


class LicenseBatchCreateResponse(BaseModel):
    items: List[LicenseAdminResponse]
    batch: "LicenseBatchResponse"
    quantity: int


class LicenseBatchResponse(BaseModel):
    id: int
    batch_code: str
    quantity: int
    created_at: datetime
    created_by: Optional[str]
    type_code: Optional[str]
    metadata: Optional[dict[str, Any]] = None

    class Config:
        orm_mode = True


class LicenseBatchListResponse(BaseModel):
    items: List[LicenseBatchResponse]
    total: int
    offset: int
    limit: int


class LicenseBatchDetailResponse(BaseModel):
    batch: LicenseBatchResponse
    licenses: List[LicenseAdminResponse]


class SoftwareSlotResponse(BaseModel):
    code: str
    name: str
    status: str
    product_line: Optional[str]
    channel: Optional[str]
    gray_ratio: Optional[int]
    notes: Optional[str]
    current_package_id: Optional[int]
    current_package_version: Optional[str]
    updated_at: datetime

    class Config:
        orm_mode = True


class SoftwarePackageResponse(BaseModel):
    id: int
    version: str
    status: str
    file_url: Optional[str]
    checksum: Optional[str]
    release_notes: Optional[str]
    is_critical: bool
    promoted_at: Optional[datetime]
    created_at: datetime

    class Config:
        orm_mode = True


class SoftwarePackageListResponse(BaseModel):
    slot_code: str
    items: List[SoftwarePackageResponse]


LicenseBatchCreateResponse.update_forward_refs()
LicenseBatchDetailResponse.update_forward_refs()

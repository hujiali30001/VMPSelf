from __future__ import annotations

from datetime import datetime
from typing import Optional

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

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


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


__all__ = [
    "ActivationRequest",
    "ActivationResponse",
    "HeartbeatRequest",
    "OfflineLicenseRequest",
    "OfflineLicenseResponse",
    "PingResponse",
    "RevokeRequest",
    "UserRegisterRequest",
    "UserRegisterResponse",
]

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class LicenseStatus(str, Enum):
    UNUSED = "unused"
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class License(Base):
    __tablename__ = "licenses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    card_code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    secret: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default=LicenseStatus.UNUSED.value)
    bound_fingerprint: Mapped[Optional[str]] = mapped_column(String(128))
    expire_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    activations: Mapped[list["Activation"]] = relationship(back_populates="license", cascade="all, delete-orphan")
    user: Mapped[Optional["User"]] = relationship(back_populates="license", uselist=False)


class Activation(Base):
    __tablename__ = "activations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    license_id: Mapped[int] = mapped_column(ForeignKey("licenses.id"), nullable=False)
    device_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    token: Mapped[Optional[str]] = mapped_column(String(256))

    license: Mapped[License] = relationship(back_populates="activations")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    license_id: Mapped[Optional[int]] = mapped_column(Integer)
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    license_id: Mapped[int] = mapped_column(ForeignKey("licenses.id"), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    license: Mapped[License] = relationship(back_populates="user")

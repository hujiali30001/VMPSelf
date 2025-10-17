from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class LicenseStatus(str, Enum):
    UNUSED = "unused"
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class LicenseCardType(Base):
    __tablename__ = "license_card_types"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(64), nullable=False)
    default_duration_days: Mapped[Optional[int]] = mapped_column(Integer)
    card_prefix: Mapped[Optional[str]] = mapped_column(String(16))
    description: Mapped[Optional[str]] = mapped_column(Text)
    color: Mapped[Optional[str]] = mapped_column(String(16))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    licenses: Mapped[list["License"]] = relationship(back_populates="card_type")


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

    card_type_id: Mapped[Optional[int]] = mapped_column(ForeignKey("license_card_types.id"))
    custom_duration_days: Mapped[Optional[int]] = mapped_column(Integer)
    card_prefix: Mapped[Optional[str]] = mapped_column(String(16))
    software_slot_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("software_slots.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )

    activations: Mapped[list["Activation"]] = relationship(back_populates="license", cascade="all, delete-orphan")
    user: Mapped[Optional["User"]] = relationship(back_populates="license", uselist=False)
    card_type: Mapped[Optional[LicenseCardType]] = relationship(back_populates="licenses")
    software_slot: Mapped[Optional["SoftwareSlot"]] = relationship(back_populates="licenses")


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


class CDNEndpointStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"


class CDNTaskStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


class CDNTaskType(str, Enum):
    PURGE = "purge"
    PREFETCH = "prefetch"


class CDNEndpoint(Base):
    __tablename__ = "cdn_endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    domain: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    origin: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default=CDNEndpointStatus.ACTIVE.value)
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    notes: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    tasks: Mapped[list["CDNTask"]] = relationship(back_populates="endpoint", cascade="all, delete-orphan")


class CDNTask(Base):
    __tablename__ = "cdn_tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("cdn_endpoints.id"), nullable=False, index=True)
    task_type: Mapped[str] = mapped_column(String(16), default=CDNTaskType.PURGE.value)
    status: Mapped[str] = mapped_column(String(16), default=CDNTaskStatus.PENDING.value)
    payload: Mapped[Optional[str]] = mapped_column(Text)
    message: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    endpoint: Mapped[CDNEndpoint] = relationship(back_populates="tasks")


class SoftwareSlotStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"


class SoftwarePackageStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    RETIRED = "retired"


class SoftwareSlot(Base):
    __tablename__ = "software_slots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    product_line: Mapped[Optional[str]] = mapped_column(String(128))
    channel: Mapped[Optional[str]] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default=SoftwareSlotStatus.ACTIVE.value)
    gray_ratio: Mapped[Optional[int]] = mapped_column(Integer)
    notes: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    packages: Mapped[list["SoftwarePackage"]] = relationship(
        back_populates="slot",
        cascade="all, delete-orphan",
        foreign_keys="SoftwarePackage.slot_id",
    )
    licenses: Mapped[list[License]] = relationship(back_populates="software_slot")
    current_package_link: Mapped[Optional["SoftwareSlotCurrentPackage"]] = relationship(
        back_populates="slot",
        cascade="all, delete-orphan",
        uselist=False,
    )

    @property
    def current_package(self) -> Optional["SoftwarePackage"]:
        if self.current_package_link:
            return self.current_package_link.package
        return None

    @property
    def current_package_id(self) -> Optional[int]:
        if self.current_package_link:
            return self.current_package_link.package_id
        return None


class SoftwarePackage(Base):
    __tablename__ = "software_packages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    slot_id: Mapped[int] = mapped_column(ForeignKey("software_slots.id"), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    file_url: Mapped[Optional[str]] = mapped_column(String(255))
    checksum: Mapped[Optional[str]] = mapped_column(String(128))
    release_notes: Mapped[Optional[str]] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default=SoftwarePackageStatus.DRAFT.value)
    is_critical: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    promoted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    slot: Mapped[SoftwareSlot] = relationship(back_populates="packages", foreign_keys=[slot_id])
    slot_current_link: Mapped[Optional["SoftwareSlotCurrentPackage"]] = relationship(
        back_populates="package",
        uselist=False,
    )


class SoftwareSlotCurrentPackage(Base):
    __tablename__ = "software_slot_current_packages"

    slot_id: Mapped[int] = mapped_column(
        ForeignKey("software_slots.id", ondelete="CASCADE"),
        primary_key=True,
    )
    package_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("software_packages.id", ondelete="SET NULL"),
        unique=True,
    )
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    slot: Mapped[SoftwareSlot] = relationship(back_populates="current_package_link")
    package: Mapped[Optional[SoftwarePackage]] = relationship(back_populates="slot_current_link")


class AdminUser(Base):
    __tablename__ = "admin_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="admin")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

from __future__ import annotations

import pytest

from app.core.settings import get_settings
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.db import models
import app.db.models  # noqa: F401  # ensure models are registered


@pytest.fixture(autouse=True)
def reset_database():
    settings = get_settings()
    original_core_whitelist = list(settings.core_ip_whitelist)
    original_core_blacklist = list(settings.core_ip_blacklist)
    original_cdn_whitelist = list(settings.cdn_ip_whitelist)
    original_cdn_manual_whitelist = list(settings.cdn_ip_manual_whitelist)
    original_cdn_blacklist = list(settings.cdn_ip_blacklist)

    settings.core_ip_whitelist = list(original_core_whitelist)
    settings.core_ip_blacklist = list(original_core_blacklist)
    settings.cdn_ip_whitelist = list(original_cdn_whitelist)
    settings.cdn_ip_manual_whitelist = list(original_cdn_manual_whitelist)
    settings.cdn_ip_blacklist = list(original_cdn_blacklist)

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        default_slot = models.SoftwareSlot(
            code="default-slot",
            name="默认软件位",
            slot_secret="default-slot-secret",
        )
        session.add(default_slot)
        session.commit()

    with SessionLocal() as session:
        from app.services.accounts import AdminUserService

        AdminUserService(session).ensure_roles()
    try:
        yield
    finally:
        settings.core_ip_whitelist = list(original_core_whitelist)
        settings.core_ip_blacklist = list(original_core_blacklist)
        settings.cdn_ip_whitelist = list(original_cdn_whitelist)
        settings.cdn_ip_manual_whitelist = list(original_cdn_manual_whitelist)
        settings.cdn_ip_blacklist = list(original_cdn_blacklist)

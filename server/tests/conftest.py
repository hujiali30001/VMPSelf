from __future__ import annotations

import pytest

from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.db import models
import app.db.models  # noqa: F401  # ensure models are registered


@pytest.fixture(autouse=True)
def reset_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        default_slot = models.SoftwareSlot(code="default-slot", name="默认软件位")
        session.add(default_slot)
        session.commit()

    with SessionLocal() as session:
        from app.services.admin_user_service import AdminUserService

        AdminUserService(session).ensure_roles()
    yield

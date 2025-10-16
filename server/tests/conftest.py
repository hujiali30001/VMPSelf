from __future__ import annotations

import pytest

from app.db.base import Base
from app.db.session import engine
import app.db.models  # noqa: F401  # ensure models are registered


@pytest.fixture(autouse=True)
def reset_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield

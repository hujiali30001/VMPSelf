from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.db import models
from app.db.session import SessionLocal
from app.main import app


def _create_license(card_code: str, *, expire_in_days: int = 30) -> models.License:
    with SessionLocal() as session:
        license_obj = models.License(
            card_code=card_code,
            secret="secret-key",
            expire_at=datetime.now(timezone.utc) + timedelta(days=expire_in_days) if expire_in_days else None,
        )
        session.add(license_obj)
        session.commit()
        session.refresh(license_obj)
        return license_obj


def test_user_registration_success():
    license_obj = _create_license("REG-CARD-1")
    client = TestClient(app)

    response = client.post(
        "/api/v1/users/register",
        json={
            "username": "new_user",
            "password": "StrongPass123!",
            "card_code": license_obj.card_code,
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "new_user"
    assert data["card_code"] == license_obj.card_code
    assert data["message"] == "registered"

    with SessionLocal() as session:
        user = session.query(models.User).filter(models.User.username == "new_user").first()
        assert user is not None
        assert user.password_hash != "StrongPass123!"
        assert user.license_id == license_obj.id

        logs = (
            session.query(models.AuditLog)
            .filter(models.AuditLog.license_id == license_obj.id, models.AuditLog.event_type == "user_register")
            .all()
        )
        assert len(logs) == 1
        assert "new_user" in (logs[0].message or "")


def test_user_registration_requires_valid_card():
    client = TestClient(app)

    response = client.post(
        "/api/v1/users/register",
        json={
            "username": "anyone",
            "password": "StrongPass123!",
            "card_code": "NOT-EXIST",
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "license_not_found"


def test_user_registration_prevents_duplicate_license():
    license_obj = _create_license("REG-CARD-2")
    client = TestClient(app)

    first = client.post(
        "/api/v1/users/register",
        json={
            "username": "owner",
            "password": "StrongPass123!",
            "card_code": license_obj.card_code,
        },
    )
    assert first.status_code == 201

    second = client.post(
        "/api/v1/users/register",
        json={
            "username": "another",
            "password": "StrongPass123!",
            "card_code": license_obj.card_code,
        },
    )
    assert second.status_code == 400
    assert second.json()["detail"] == "license_already_bound"


def test_user_registration_rejects_short_password():
    license_obj = _create_license("REG-CARD-3")
    client = TestClient(app)

    response = client.post(
        "/api/v1/users/register",
        json={
            "username": "shortpwd",
            "password": "123",
            "card_code": license_obj.card_code,
        },
    )

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(err.get("loc") == ["body", "password"] for err in detail)


def test_user_registration_rejects_expired_license():
    license_obj = _create_license("REG-CARD-4", expire_in_days=-1)
    client = TestClient(app)

    response = client.post(
        "/api/v1/users/register",
        json={
            "username": "expired",
            "password": "StrongPass123!",
            "card_code": license_obj.card_code,
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "license_expired"

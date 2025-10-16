from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware.cdn_guard import CDNGuardMiddleware


def create_app():
    app = FastAPI()

    @app.get("/secure")
    def secure():
        return {"ok": True}

    @app.get("/public")
    def public():
        return {"ok": True}

    app.add_middleware(
        CDNGuardMiddleware,
        header_name="X-Edge-Token",
        shared_token="edge-secret",
        allow_paths={"/public"},
        ip_header="X-Forwarded-For",
        ip_whitelist={"203.0.113.10"},
    )
    return app


def test_cdn_guard_blocks_without_token():
    client = TestClient(create_app())
    response = client.get("/secure")
    assert response.status_code == 403


def test_cdn_guard_allows_public_route_without_token():
    client = TestClient(create_app())
    response = client.get("/public")
    assert response.status_code == 200


def test_cdn_guard_blocks_untrusted_ip():
    client = TestClient(create_app())
    response = client.get(
        "/secure",
        headers={"X-Edge-Token": "edge-secret", "X-Forwarded-For": "198.51.100.5"},
    )
    assert response.status_code == 403


def test_cdn_guard_allows_valid_request():
    client = TestClient(create_app())
    response = client.get(
        "/secure",
        headers={"X-Edge-Token": "edge-secret", "X-Forwarded-For": "203.0.113.10"},
    )
    assert response.status_code == 200
    assert response.json()["ok"] is True

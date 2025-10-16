from fastapi.testclient import TestClient

from app.main import app


def test_ping():
    client = TestClient(app)
    response = client.get("/api/v1/ping")
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "pong"
    assert "server_time" in data

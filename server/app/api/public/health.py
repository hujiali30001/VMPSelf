from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

from app.schemas import PingResponse

router = APIRouter(tags=["health"])


@router.get("/ping", response_model=PingResponse)
def ping():
    return PingResponse(
        message="pong",
        server_time=datetime.now(timezone.utc),
    )
    return PingResponse(message="pong", server_time=datetime.now(timezone.utc))

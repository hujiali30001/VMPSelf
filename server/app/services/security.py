from __future__ import annotations

import base64
import hmac
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Optional, Tuple

import jwt

from app.core.settings import get_settings

settings = get_settings()
def _derive_key(shared_secret: Optional[str] = None) -> bytes:
    secret = shared_secret or settings.hmac_secret
    return secret.encode("utf-8")


def sign_message(message: str, shared_secret: Optional[str] = None) -> str:
    digest = hmac.new(_derive_key(shared_secret), message.encode("utf-8"), sha256).digest()
    return base64.b64encode(digest).decode("utf-8")


def verify_signature(
    card_code: str,
    fingerprint: str,
    timestamp: int,
    signature: str,
    shared_secret: Optional[str] = None,
) -> bool:
    message = f"{card_code}|{fingerprint}|{timestamp}".encode("utf-8")
    expected = hmac.new(_derive_key(shared_secret), message, sha256).digest()
    try:
        provided = base64.b64decode(signature)
    except Exception:
        return False
    return hmac.compare_digest(expected, provided)


def issue_token(card_code: str, fingerprint: str) -> Tuple[str, datetime]:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.token_ttl_minutes)
    payload = {
        "card": card_code,
        "fp": fingerprint,
        "exp": int(expires_at.timestamp()),
    }
    token = jwt.encode(payload, settings.hmac_secret, algorithm="HS256")
    return token, expires_at

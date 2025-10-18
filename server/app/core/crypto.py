from __future__ import annotations

import base64
import hashlib
from functools import lru_cache
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from app.core.settings import get_settings


@lru_cache(maxsize=1)
def _get_fernet() -> Fernet:
    settings = get_settings()
    raw_key = settings.cdn_credentials_key or settings.hmac_secret
    digest = hashlib.sha256(raw_key.encode("utf-8")).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def encrypt_secret(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    trimmed = value.strip()
    if not trimmed:
        return None
    token = _get_fernet().encrypt(trimmed.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_secret(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    try:
        value = _get_fernet().decrypt(token.encode("utf-8"))
    except InvalidToken:
        return None
    return value.decode("utf-8")


__all__ = ["encrypt_secret", "decrypt_secret"]

from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import BaseSettings, Field, validator


class Settings(BaseSettings):
    app_name: str = "VMP Auth Service"
    environment: str = Field("development", env="VMP_ENV")
    sqlite_path: Path = Field(Path("data/license.db"), env="VMP_SQLITE_PATH")
    hmac_secret: str = Field("change-me", env="VMP_HMAC_SECRET")
    token_ttl_minutes: int = Field(60 * 24, env="VMP_TOKEN_TTL")
    allow_offline_minutes: int = Field(60 * 24 * 7, env="VMP_OFFLINE_TTL")
    heartbeat_interval_seconds: int = Field(300, env="VMP_HEARTBEAT_INTERVAL")
    cors_allow_origins: list[str] = Field(default_factory=lambda: ["*"])
    cdn_enforced: bool = Field(False, env="VMP_CDN_ENFORCED")
    cdn_token: Optional[str] = Field(None, env="VMP_CDN_TOKEN")
    cdn_header_name: str = Field("X-Edge-Token", env="VMP_CDN_HEADER")
    cdn_ip_header: str = Field("X-Forwarded-For", env="VMP_CDN_IP_HEADER")
    cdn_ip_whitelist: list[str] = Field(default_factory=list)
    cdn_exempt_paths: list[str] = Field(default_factory=lambda: ["/api/v1/ping"])
    cdn_credentials_key: Optional[str] = Field(None, env="VMP_CDN_CREDENTIALS_KEY")
    admin_username: str = Field("admin", env="VMP_ADMIN_USER")
    admin_password: str = Field("change-me", env="VMP_ADMIN_PASS")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

    @validator("cdn_ip_whitelist", pre=True)
    def _parse_ip_whitelist(cls, value):  # type: ignore[no-self-argument]
        if isinstance(value, str):
            if not value.strip():
                return []
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @validator("cdn_exempt_paths", pre=True)
    def _parse_exempt_paths(cls, value):  # type: ignore[no-self-argument]
        if isinstance(value, str):
            if not value.strip():
                return []
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


@lru_cache()
def get_settings() -> Settings:
    settings = Settings()
    settings.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    return settings

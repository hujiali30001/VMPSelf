#!/usr/bin/env python
from __future__ import annotations

import argparse
import secrets
from datetime import datetime, timedelta, timezone

from app.core.settings import get_settings
from app.db import Base, License
from app.db.session import SessionLocal, engine


settings = get_settings()


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    print(f"Database initialized at {settings.sqlite_path}")


def create_license(card_code: str | None, ttl_days: int) -> None:
    code = card_code or secrets.token_hex(8)
    secret = secrets.token_urlsafe(32)
    with SessionLocal() as session:
        expires = datetime.now(timezone.utc) + timedelta(days=ttl_days)
        license_obj = License(
            card_code=code,
            secret=secret,
            expire_at=expires,
        )
        session.add(license_obj)
        session.commit()
        print(f"License created:\n  Card: {code}\n  Secret: {secret}\n  Expires: {expires.isoformat()}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage VMP Auth Service")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init-db", help="Initialize SQLite database")

    create_parser = sub.add_parser("create-license", help="Create a new license")
    create_parser.add_argument("--card", dest="card_code", help="Optional custom card code")
    create_parser.add_argument("--ttl", dest="ttl", type=int, default=30, help="Validity in days")

    args = parser.parse_args()

    if args.command == "init-db":
        init_db()
    elif args.command == "create-license":
        create_license(args.card_code, args.ttl)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

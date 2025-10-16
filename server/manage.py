#!/usr/bin/env python
from __future__ import annotations

import argparse
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.core.settings import get_settings
from app.db import Base, License, LicenseStatus
from app.db.session import SessionLocal, engine
from app.services.license_service import LicenseService


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


def list_licenses(status: str, limit: int) -> None:
    with SessionLocal() as session:
        stmt = select(License).order_by(License.created_at.desc())
        if status != "all":
            stmt = stmt.where(License.status == status)
        if limit > 0:
            stmt = stmt.limit(limit)

        rows = session.scalars(stmt).all()
        if not rows:
            print("No licenses found.")
            return

        header = f"{'CARD CODE':<20} {'STATUS':<8} {'EXPIRES':<25} {'BOUND FINGERPRINT'}"
        print(header)
        print("-" * len(header))
        for license_obj in rows:
            expires = license_obj.expire_at.isoformat() if license_obj.expire_at else "--"
            fingerprint = license_obj.bound_fingerprint or "--"
            print(f"{license_obj.card_code:<20} {license_obj.status:<8} {expires:<25} {fingerprint}")


def revoke_license(card_code: str) -> None:
    with SessionLocal() as session:
        service = LicenseService(session)
        if service.revoke(card_code):
            print(f"License {card_code} revoked.")
        else:
            print(f"License {card_code} not found.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage VMP Auth Service")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init-db", help="Initialize SQLite database")

    create_parser = sub.add_parser("create-license", help="Create a new license")
    create_parser.add_argument("--card", dest="card_code", help="Optional custom card code")
    create_parser.add_argument("--ttl", dest="ttl", type=int, default=30, help="Validity in days")

    list_parser = sub.add_parser("list-licenses", help="List existing licenses")
    list_parser.add_argument(
        "--status",
        choices=[choice.value for choice in LicenseStatus] + ["all"],
        default="all",
        help="Filter by license status",
    )
    list_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of records to display (<=0 for no limit)",
    )

    revoke_parser = sub.add_parser("revoke-license", help="Revoke an existing license")
    revoke_parser.add_argument("card_code", help="Card code to revoke")

    args = parser.parse_args()

    if args.command == "init-db":
        init_db()
    elif args.command == "create-license":
        create_license(args.card_code, args.ttl)
    elif args.command == "list-licenses":
        list_licenses(args.status, args.limit)
    elif args.command == "revoke-license":
        revoke_license(args.card_code)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

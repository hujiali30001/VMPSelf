#!/usr/bin/env python
from __future__ import annotations

import argparse
from pathlib import Path

from sqlalchemy import inspect, select, text

from sqlalchemy import select

from app.core.settings import get_settings
from app.db import Base, License, LicenseCardType, LicenseStatus
from app.db.session import SessionLocal, engine, database_url
from app.services.licensing import LicenseService

from alembic import command
from alembic.config import Config

BASE_DIR = Path(__file__).resolve().parent


settings = get_settings()


DEFAULT_CARD_TYPES: list[dict[str, object]] = [
    {
        "code": "day",
        "display_name": "天卡",
        "default_duration_days": 1,
        "card_prefix": "D-",
        "color": "#38bdf8",
        "sort_order": 10,
    },
    {
        "code": "week",
        "display_name": "周卡",
        "default_duration_days": 7,
        "card_prefix": "W-",
        "color": "#22d3ee",
        "sort_order": 20,
    },
    {
        "code": "month",
        "display_name": "月卡",
        "default_duration_days": 30,
        "card_prefix": "M-",
        "color": "#6366f1",
        "sort_order": 30,
    },
    {
        "code": "quarter",
        "display_name": "季卡",
        "default_duration_days": 90,
        "card_prefix": "Q-",
        "color": "#f97316",
        "sort_order": 40,
    },
    {
        "code": "year",
        "display_name": "年卡",
        "default_duration_days": 365,
        "card_prefix": "Y-",
        "color": "#16a34a",
        "sort_order": 50,
    },
]


def _ensure_card_type_schema() -> None:
    Base.metadata.create_all(bind=engine)

    inspector = inspect(engine)
    tables = inspector.get_table_names()

    if "license_card_types" not in tables:
        LicenseCardType.__table__.create(bind=engine)

    license_columns = {column["name"] for column in inspector.get_columns("licenses")}
    with engine.begin() as conn:
        if "card_type_id" not in license_columns:
            conn.execute(text("ALTER TABLE licenses ADD COLUMN card_type_id INTEGER"))
        if "custom_duration_days" not in license_columns:
            conn.execute(text("ALTER TABLE licenses ADD COLUMN custom_duration_days INTEGER"))
        if "card_prefix" not in license_columns:
            conn.execute(text("ALTER TABLE licenses ADD COLUMN card_prefix VARCHAR(16)"))

    _run_alembic_upgrade()


def _run_alembic_upgrade() -> None:
    alembic_cfg = Config(str(BASE_DIR / "alembic.ini"))
    alembic_cfg.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(alembic_cfg, "head")


def _seed_default_card_types() -> None:
    with SessionLocal() as session:
        existing_codes = {
            row[0]
            for row in session.execute(select(LicenseCardType.code)).all()
        }
        to_insert = []
        for payload in DEFAULT_CARD_TYPES:
            if payload["code"] not in existing_codes:
                to_insert.append(LicenseCardType(**payload))

        if to_insert:
            session.add_all(to_insert)
            session.commit()
            print(f"Inserted default card types: {', '.join(p.code for p in to_insert)}")


def init_db() -> None:
    _ensure_card_type_schema()
    _seed_default_card_types()
    print(f"Database initialized at {settings.sqlite_path}")


def create_license(
    card_code: str | None,
    ttl_days: int | None,
    type_code: str | None,
    quantity: int,
    custom_prefix: str | None,
    custom_ttl_days: int | None,
) -> None:
    with SessionLocal() as session:
        service = LicenseService(session)
        try:
            licenses, batch_id = service.create_licenses(
                type_code=type_code,
                card_code=card_code,
                quantity=quantity,
                custom_prefix=custom_prefix,
                ttl_days=ttl_days,
                custom_ttl_days=custom_ttl_days,
            )
        except ValueError as exc:
            raise SystemExit(f"Failed to create license(s): {exc}") from exc

        print(f"Batch {batch_id} created {len(licenses)} license(s):")
        for license_obj in licenses:
            type_info = license_obj.card_type.code if license_obj.card_type else "--"
            expires = license_obj.expire_at.isoformat() if license_obj.expire_at else "never"
            print(
                "  - {code} | type={type} | ttl={ttl} | prefix={prefix} | secret={secret}".format(
                    code=license_obj.card_code,
                    type=type_info,
                    ttl=license_obj.custom_duration_days
                    if license_obj.custom_duration_days is not None
                    else (license_obj.card_type.default_duration_days if license_obj.card_type else "--"),
                    prefix=license_obj.card_prefix or "--",
                    secret=license_obj.secret,
                )
            )
            print(f"    expires: {expires}")


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

        header = f"{'CARD CODE':<20} {'TYPE':<10} {'STATUS':<8} {'EXPIRES':<25} {'PREFIX':<8} {'BOUND FINGERPRINT'}"
        print(header)
        print("-" * len(header))
        for license_obj in rows:
            expires = license_obj.expire_at.isoformat() if license_obj.expire_at else "--"
            fingerprint = license_obj.bound_fingerprint or "--"
            type_code = license_obj.card_type.code if license_obj.card_type else "--"
            prefix = license_obj.card_prefix or "--"
            print(
                f"{license_obj.card_code:<20} {type_code:<10} {license_obj.status:<8} {expires:<25} {prefix:<8} {fingerprint}"
            )


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

    create_parser = sub.add_parser("create-license", help="Create one or more licenses")
    create_parser.add_argument("--card", dest="card_code", help="Optional custom card code (single license only)")
    create_parser.add_argument("--ttl", dest="ttl", type=int, default=None, help="Default validity in days (fallback 30)")
    create_parser.add_argument("--type", dest="type_code", help="License card type code to apply")
    create_parser.add_argument("--quantity", dest="quantity", type=int, default=1, help="Number of licenses to generate")
    create_parser.add_argument("--prefix", dest="custom_prefix", help="Override generated card prefix")
    create_parser.add_argument(
        "--custom-ttl",
        dest="custom_ttl",
        type=int,
        default=None,
        help="Override default duration in days for the selected type",
    )

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
        ttl_value = args.ttl
        if ttl_value is None and args.type_code is None and args.custom_ttl is None:
            ttl_value = 30
        create_license(
            args.card_code,
            ttl_value,
            args.type_code,
            args.quantity,
            args.custom_prefix,
            args.custom_ttl,
        )
    elif args.command == "list-licenses":
        list_licenses(args.status, args.limit)
    elif args.command == "revoke-license":
        revoke_license(args.card_code)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

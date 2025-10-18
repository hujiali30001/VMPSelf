"""Initial database schema

Revision ID: 20251010_initial_schema
Revises:
Create Date: 2025-10-10
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20251010_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "license_card_types",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("code", sa.String(length=32), nullable=False, unique=True),
        sa.Column("display_name", sa.String(length=64), nullable=False),
        sa.Column("default_duration_days", sa.Integer(), nullable=True),
        sa.Column("card_prefix", sa.String(length=16), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("color", sa.String(length=16), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "licenses",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("card_code", sa.String(length=64), nullable=False, unique=True),
        sa.Column("secret", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="unused"),
        sa.Column("bound_fingerprint", sa.String(length=128), nullable=True),
        sa.Column("expire_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("card_type_id", sa.Integer(), sa.ForeignKey("license_card_types.id", ondelete="SET NULL"), nullable=True),
        sa.Column("custom_duration_days", sa.Integer(), nullable=True),
        sa.Column("card_prefix", sa.String(length=16), nullable=True),
    )
    op.create_index("ix_licenses_card_type_id", "licenses", ["card_type_id"])
    op.create_index("ix_licenses_status", "licenses", ["status"])

    op.create_table(
        "activations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("license_id", sa.Integer(), sa.ForeignKey("licenses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_fingerprint", sa.String(length=128), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("token", sa.String(length=256), nullable=True),
    )
    op.create_index("ix_activations_license_id", "activations", ["license_id"])

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(length=64), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("license_id", sa.Integer(), sa.ForeignKey("licenses.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "admin_users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(length=64), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="admin"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("license_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "software_slots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("code", sa.String(length=64), nullable=False, unique=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("product_line", sa.String(length=128), nullable=True),
        sa.Column("channel", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column("gray_ratio", sa.Integer(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("current_package_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "software_packages",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("slot_id", sa.Integer(), sa.ForeignKey("software_slots.id", ondelete="CASCADE"), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("file_url", sa.String(length=255), nullable=True),
        sa.Column("checksum", sa.String(length=128), nullable=True),
        sa.Column("release_notes", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="draft"),
        sa.Column("is_critical", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_software_packages_slot_id", "software_packages", ["slot_id"])

    op.create_table(
        "cdn_endpoints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("domain", sa.String(length=128), nullable=False, unique=True),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("origin", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "cdn_tasks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("endpoint_id", sa.Integer(), sa.ForeignKey("cdn_endpoints.id", ondelete="CASCADE"), nullable=False),
        sa.Column("task_type", sa.String(length=16), nullable=False, server_default="purge"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("payload", sa.Text(), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_cdn_tasks_endpoint_id", "cdn_tasks", ["endpoint_id"])


def downgrade() -> None:
    op.drop_index("ix_cdn_tasks_endpoint_id", table_name="cdn_tasks")
    op.drop_table("cdn_tasks")

    op.drop_table("cdn_endpoints")

    op.drop_index("ix_software_packages_slot_id", table_name="software_packages")
    op.drop_table("software_packages")

    op.drop_table("software_slots")

    op.drop_table("audit_logs")

    op.drop_table("admin_users")

    op.drop_table("users")

    op.drop_index("ix_activations_license_id", table_name="activations")
    op.drop_table("activations")

    op.drop_index("ix_licenses_status", table_name="licenses")
    op.drop_index("ix_licenses_card_type_id", table_name="licenses")
    op.drop_table("licenses")

    op.drop_table("license_card_types")

"""Add license batches and metadata fields

Revision ID: 20251019_add_license_batches
Revises: 20251019_extend_audit_logs
Create Date: 2025-10-18
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision: str = "20251019_add_license_batches"
down_revision: Union[str, None] = "20251019_extend_audit_logs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    sqlite = dialect == "sqlite"
    inspector = inspect(bind)

    def _drop_sqlite_temp_table(name: str) -> None:
        if sqlite:
            bind.execute(sa.text(f'DROP TABLE IF EXISTS "{name}"'))

    if not inspector.has_table("license_batches"):
        op.create_table(
            "license_batches",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("batch_code", sa.String(length=32), nullable=False, unique=True),
            sa.Column("type_id", sa.Integer(), nullable=True),
            sa.Column("quantity", sa.Integer(), nullable=False),
            sa.Column("created_by", sa.String(length=128), nullable=True),
            sa.Column("metadata", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["type_id"], ["license_card_types.id"], ondelete="SET NULL"),
        )
        op.create_index("ix_license_batches_batch_code", "license_batches", ["batch_code"], unique=True)

    card_type_columns = {col["name"] for col in inspector.get_columns("license_card_types")}
    if "metadata" not in card_type_columns:
        if sqlite:
            _drop_sqlite_temp_table("_alembic_tmp_license_card_types")
            with op.batch_alter_table("license_card_types") as batch_op:
                batch_op.add_column(sa.Column("metadata", sa.JSON(), nullable=True))
        else:
            op.add_column("license_card_types", sa.Column("metadata", sa.JSON(), nullable=True))

    license_columns = {col["name"] for col in inspector.get_columns("licenses")}
    license_indexes = {idx["name"] for idx in inspector.get_indexes("licenses")}
    license_fk_names = {fk.get("name") for fk in inspector.get_foreign_keys("licenses") if fk.get("name")}

    needs_batch_column = "batch_id" not in license_columns
    needs_notes_column = "notes" not in license_columns
    needs_batch_index = "ix_licenses_batch_id" not in license_indexes
    needs_batch_fk = "fk_licenses_batch_id" not in license_fk_names

    if sqlite:
        if needs_batch_column or needs_notes_column or needs_batch_index or needs_batch_fk:
            _drop_sqlite_temp_table("_alembic_tmp_licenses")
            with op.batch_alter_table("licenses") as batch_op:
                if needs_batch_column:
                    batch_op.add_column(sa.Column("batch_id", sa.Integer(), nullable=True))
                if needs_notes_column:
                    batch_op.add_column(sa.Column("notes", sa.Text(), nullable=True))
                if needs_batch_index:
                    batch_op.create_index("ix_licenses_batch_id", ["batch_id"], unique=False)
                if needs_batch_fk:
                    batch_op.create_foreign_key(
                        "fk_licenses_batch_id",
                        "license_batches",
                        ["batch_id"],
                        ["id"],
                        ondelete="SET NULL",
                    )
    else:
        if needs_batch_column:
            op.add_column("licenses", sa.Column("batch_id", sa.Integer(), nullable=True))
        if needs_notes_column:
            op.add_column("licenses", sa.Column("notes", sa.Text(), nullable=True))
        if needs_batch_index:
            op.create_index("ix_licenses_batch_id", "licenses", ["batch_id"], unique=False)
        if needs_batch_fk:
            op.create_foreign_key(
                "fk_licenses_batch_id",
                "licenses",
                "license_batches",
                ["batch_id"],
                ["id"],
                ondelete="SET NULL",
            )


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "sqlite":
        with op.batch_alter_table("licenses") as batch_op:
            batch_op.drop_constraint("fk_licenses_batch_id", type_="foreignkey")
            batch_op.drop_index("ix_licenses_batch_id")
            batch_op.drop_column("notes")
            batch_op.drop_column("batch_id")
    else:
        op.drop_constraint("fk_licenses_batch_id", "licenses", type_="foreignkey")
        op.drop_index("ix_licenses_batch_id", table_name="licenses")
        op.drop_column("licenses", "notes")
        op.drop_column("licenses", "batch_id")

    if dialect == "sqlite":
        with op.batch_alter_table("license_card_types") as batch_op:
            batch_op.drop_column("metadata")
    else:
        op.drop_column("license_card_types", "metadata")

    op.drop_index("ix_license_batches_batch_code", table_name="license_batches")
    op.drop_table("license_batches")

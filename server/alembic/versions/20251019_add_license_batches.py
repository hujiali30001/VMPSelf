"""Add license batches and metadata fields

Revision ID: 20251019_add_license_batches
Revises: 20251019_extend_audit_logs
Create Date: 2025-10-18
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "20251019_add_license_batches"
down_revision: Union[str, None] = "20251019_extend_audit_logs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

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

    if dialect == "sqlite":
        with op.batch_alter_table("license_card_types") as batch_op:
            batch_op.add_column(sa.Column("metadata", sa.JSON(), nullable=True))
    else:
        op.add_column("license_card_types", sa.Column("metadata", sa.JSON(), nullable=True))

    if dialect == "sqlite":
        with op.batch_alter_table("licenses") as batch_op:
            batch_op.add_column(sa.Column("batch_id", sa.Integer(), nullable=True))
            batch_op.add_column(sa.Column("notes", sa.Text(), nullable=True))
            batch_op.create_index("ix_licenses_batch_id", ["batch_id"], unique=False)
            batch_op.create_foreign_key(
                "fk_licenses_batch_id",
                "license_batches",
                ["batch_id"],
                ["id"],
                ondelete="SET NULL",
            )
    else:
        op.add_column("licenses", sa.Column("batch_id", sa.Integer(), nullable=True))
        op.add_column("licenses", sa.Column("notes", sa.Text(), nullable=True))
        op.create_index("ix_licenses_batch_id", "licenses", ["batch_id"], unique=False)
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

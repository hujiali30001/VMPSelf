"""Add software_slot_id to licenses

Revision ID: 20251019_add_license_slot_fk
Revises: 20251018_split_slot_current_package
Create Date: 2025-10-18
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "20251019_add_license_slot_fk"
down_revision: Union[str, None] = "20251018_split_slot_current_package"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    existing_columns = {column["name"] for column in inspector.get_columns("licenses")}
    existing_indexes = {index["name"] for index in inspector.get_indexes("licenses")}
    existing_foreign_keys = {fk["name"] for fk in inspector.get_foreign_keys("licenses") if fk.get("name")}

    dialect = bind.dialect.name

    if dialect == "sqlite":
        with op.batch_alter_table("licenses") as batch_op:
            if "software_slot_id" not in existing_columns:
                batch_op.add_column(sa.Column("software_slot_id", sa.Integer(), nullable=True))
            if "ix_licenses_software_slot_id" not in existing_indexes:
                batch_op.create_index(
                    "ix_licenses_software_slot_id",
                    ["software_slot_id"],
                    unique=False,
                )
            if "fk_licenses_software_slot_id" not in existing_foreign_keys:
                batch_op.create_foreign_key(
                    "fk_licenses_software_slot_id",
                    "software_slots",
                    ["software_slot_id"],
                    ["id"],
                    ondelete="SET NULL",
                )
    else:
        if "software_slot_id" not in existing_columns:
            op.add_column("licenses", sa.Column("software_slot_id", sa.Integer(), nullable=True))

        if "ix_licenses_software_slot_id" not in existing_indexes:
            op.create_index("ix_licenses_software_slot_id", "licenses", ["software_slot_id"], unique=False)

        if "fk_licenses_software_slot_id" not in existing_foreign_keys:
            op.create_foreign_key(
                "fk_licenses_software_slot_id",
                "licenses",
                "software_slots",
                ["software_slot_id"],
                ["id"],
                ondelete="SET NULL",
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    existing_indexes = {index["name"] for index in inspector.get_indexes("licenses")}
    existing_foreign_keys = {fk["name"] for fk in inspector.get_foreign_keys("licenses") if fk.get("name")}
    existing_columns = {column["name"] for column in inspector.get_columns("licenses")}

    dialect = bind.dialect.name

    if dialect == "sqlite":
        with op.batch_alter_table("licenses") as batch_op:
            if "fk_licenses_software_slot_id" in existing_foreign_keys:
                batch_op.drop_constraint("fk_licenses_software_slot_id", type_="foreignkey")

            if "ix_licenses_software_slot_id" in existing_indexes:
                batch_op.drop_index("ix_licenses_software_slot_id")

            if "software_slot_id" in existing_columns:
                batch_op.drop_column("software_slot_id")
    else:
        if "fk_licenses_software_slot_id" in existing_foreign_keys:
            op.drop_constraint("fk_licenses_software_slot_id", "licenses", type_="foreignkey")

        if "ix_licenses_software_slot_id" in existing_indexes:
            op.drop_index("ix_licenses_software_slot_id", table_name="licenses")

        if "software_slot_id" in existing_columns:
            op.drop_column("licenses", "software_slot_id")

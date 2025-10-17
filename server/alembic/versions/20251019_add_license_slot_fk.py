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
    op.add_column("licenses", sa.Column("software_slot_id", sa.Integer(), nullable=True))
    op.create_index("ix_licenses_software_slot_id", "licenses", ["software_slot_id"], unique=False)
    op.create_foreign_key(
        "fk_licenses_software_slot_id",
        "licenses",
        "software_slots",
        ["software_slot_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_licenses_software_slot_id", "licenses", type_="foreignkey")
    op.drop_index("ix_licenses_software_slot_id", table_name="licenses")
    op.drop_column("licenses", "software_slot_id")

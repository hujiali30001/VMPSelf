"""Add slot secrets and migration flag

Revision ID: 20251020_add_slot_secrets
Revises: 20251020_add_access_rules
Create Date: 2025-10-20
"""

from typing import Sequence, Union
import secrets

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import expression

# revision identifiers, used by Alembic.
revision: str = "20251020_add_slot_secrets"
down_revision: Union[str, None] = "20251020_add_access_rules"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    existing_slot_columns = {column["name"] for column in inspector.get_columns("software_slots")}
    if "slot_secret" not in existing_slot_columns:
        with op.batch_alter_table("software_slots") as batch_op:
            batch_op.add_column(sa.Column("slot_secret", sa.String(length=128), nullable=True))

    slots_table = sa.table(
        "software_slots",
        sa.column("id", sa.Integer()),
        sa.column("slot_secret", sa.String(length=128)),
    )

    result = bind.execute(sa.select(slots_table.c.id, slots_table.c.slot_secret))
    rows = result.fetchall()
    for row in rows:
        if not row.slot_secret:
            bind.execute(
                sa.update(slots_table)
                .where(slots_table.c.id == row.id)
                .values(slot_secret=secrets.token_urlsafe(32))
            )

    inspector = sa.inspect(bind)
    existing_license_columns = {column["name"] for column in inspector.get_columns("licenses")}
    if "secret_migrated" not in existing_license_columns:
        with op.batch_alter_table("licenses") as batch_op:
            batch_op.add_column(
                sa.Column(
                    "secret_migrated",
                    sa.Boolean(),
                    nullable=False,
                    server_default=expression.false(),
                )
            )
            batch_op.alter_column("secret_migrated", server_default=None)

    existing_license_indexes = {index["name"] for index in inspector.get_indexes("licenses")}
    if "ix_licenses_legacy_secret" not in existing_license_indexes:
        op.create_index("ix_licenses_legacy_secret", "licenses", ["secret"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    existing_slot_columns = {column["name"] for column in inspector.get_columns("software_slots")}
    if "slot_secret" in existing_slot_columns:
        with op.batch_alter_table("software_slots") as batch_op:
            batch_op.drop_column("slot_secret")

    existing_license_columns = {column["name"] for column in inspector.get_columns("licenses")}
    if "secret_migrated" in existing_license_columns:
        with op.batch_alter_table("licenses") as batch_op:
            batch_op.drop_column("secret_migrated")

    existing_license_indexes = {index["name"] for index in inspector.get_indexes("licenses")}
    if "ix_licenses_legacy_secret" in existing_license_indexes:
        op.drop_index("ix_licenses_legacy_secret", table_name="licenses")

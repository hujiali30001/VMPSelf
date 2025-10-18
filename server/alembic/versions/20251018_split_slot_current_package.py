from __future__ import annotations

from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "20251018_split_slot_current_package"
down_revision = "20251010_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())

    if "software_slot_current_packages" not in table_names:
        op.create_table(
            "software_slot_current_packages",
            sa.Column(
                "slot_id",
                sa.Integer(),
                sa.ForeignKey("software_slots.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            sa.Column(
                "package_id",
                sa.Integer(),
                sa.ForeignKey("software_packages.id", ondelete="SET NULL"),
                nullable=True,
                unique=True,
            ),
            sa.Column(
                "assigned_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
        )

    if "software_slots" not in table_names:
        return

    slot_columns = {column["name"] for column in inspector.get_columns("software_slots")}
    if "current_package_id" not in slot_columns:
        return

    rows = bind.execute(
        sa.text(
            "SELECT id AS slot_id, current_package_id AS package_id FROM software_slots "
            "WHERE current_package_id IS NOT NULL"
        )
    ).fetchall()

    if rows:
        for row in rows:
            bind.execute(
                sa.text(
                    "INSERT INTO software_slot_current_packages (slot_id, package_id, assigned_at) "
                    "VALUES (:slot_id, :package_id, :assigned_at)"
                ),
                {
                    "slot_id": row.slot_id,
                    "package_id": row.package_id,
                    "assigned_at": datetime.now(timezone.utc),
                },
            )

    fk_names = [fk["name"] for fk in inspector.get_foreign_keys("software_slots") if "current_package_id" in fk.get("constrained_columns", [])]

    with op.batch_alter_table("software_slots") as batch_op:
        for fk_name in fk_names:
            if fk_name:
                batch_op.drop_constraint(fk_name, type_="foreignkey")
        batch_op.drop_column("current_package_id")


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())

    if "software_slots" not in table_names:
        return

    with op.batch_alter_table("software_slots") as batch_op:
        batch_op.add_column(sa.Column("current_package_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_software_slots_current_package_id",
            "software_packages",
            ["current_package_id"],
            ["id"],
        )

    if "software_slot_current_packages" in table_names:
        rows = bind.execute(
            sa.text(
                "SELECT slot_id, package_id FROM software_slot_current_packages WHERE package_id IS NOT NULL"
            )
        ).fetchall()
        for row in rows:
            bind.execute(
                sa.text(
                    "UPDATE software_slots SET current_package_id = :package_id WHERE id = :slot_id"
                ),
                {"slot_id": row.slot_id, "package_id": row.package_id},
            )
        op.drop_table("software_slot_current_packages")

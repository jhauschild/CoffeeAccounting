"""user identity restore stash and alumni anonymization counter

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-03

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0002"
down_revision: Union[str, Sequence[str], None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "anonymization_counters",
        sa.Column("name", sa.String(length=32), nullable=False),
        sa.Column("value", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("name", name=op.f("pk_anonymization_counters")),
    )
    op.execute(sa.text("INSERT INTO anonymization_counters (name, value) VALUES ('alumni', 0)"))

    op.create_table(
        "user_identity_restores",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("display_name", sa.String(length=60), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("username_normalized", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=True),
        sa.Column("reason", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "reason IN ('self', 'admin', 'inactive')",
            name=op.f("ck_user_identity_restores_reason_valid"),
        ),
        sa.CheckConstraint("length(display_name) > 0", name=op.f("ck_user_identity_restores_display_name_nonempty")),
        sa.CheckConstraint("length(username) > 0", name=op.f("ck_user_identity_restores_username_nonempty")),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_user_identity_restores_user_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_identity_restores")),
        sa.UniqueConstraint("user_id", name=op.f("uq_user_identity_restores_user_id")),
        sa.UniqueConstraint(
            "username_normalized", name=op.f("uq_user_identity_restores_username_normalized")
        ),
    )
    op.create_index(
        op.f("ix_user_identity_restores_expires_at"), "user_identity_restores", ["expires_at"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_user_identity_restores_expires_at"), table_name="user_identity_restores")
    op.drop_table("user_identity_restores")
    op.drop_table("anonymization_counters")

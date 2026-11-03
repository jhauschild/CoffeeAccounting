"""All database tables (PROMPT §4–§7, docs/ARCHITECTURE.md "Schema").

Every invariant from PROMPT §4 is mirrored as a CHECK constraint or (partial) unique
index here and in the initial Alembic migration. Timestamps are stored as UTC and
always returned timezone-aware (`UTCDateTime`).

`effective_users` is a SQL view (created in the migration) mapping every user id to the
id it counts for after merges; it lives in a separate MetaData so that Alembic does not
try to create it as a table.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    TypeDecorator,
    Uuid,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

# Field length limits shared with validation code.
DISPLAY_NAME_MAX = 60
CHAIR_FULL_NAME_MAX = 120
CHAIR_SHORT_NAME_MAX = 20
NOTE_MAX = 500

USER_STATUSES = ("active", "inactive", "merged")
EVENT_TYPES = ("single", "double", "reversal", "adjustment")
COFFEE_KINDS = ("single", "double")
COFFEE_QUANTITY = {"single": 1, "double": 2}
ADMIN_ROLES = ("global", "chair")  # role "chair" is shown in the UI as "group admin"
ACCOUNT_KINDS = ("member", "guest")
PAYMENT_KINDS = ("cash", "bookkeeping")
PENDING_ACTION_KINDS = COFFEE_KINDS + ("view_site",)
IDENTITY_RESTORE_REASONS = ("self", "admin", "inactive")
USERNAME_MAX = 64
EMAIL_MAX = 254
ACTOR_TYPES = ("admin", "user", "system")


def _now() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator):
    """Stores naive UTC (SQLite has no tz support); always returns aware UTC datetimes."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime given; use timezone-aware UTC datetimes")
        value = value.astimezone(UTC)
        return value.replace(tzinfo=None) if dialect.name == "sqlite" else value

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def _in(col: str, values: tuple[str, ...]) -> str:
    return f"{col} IN ({', '.join(repr(v) for v in values)})"


class Chair(Base):
    __tablename__ = "chairs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    full_name: Mapped[str] = mapped_column(String(CHAIR_FULL_NAME_MAX))
    short_name: Mapped[str] = mapped_column(String(CHAIR_SHORT_NAME_MAX), unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)

    __table_args__ = (
        CheckConstraint("length(full_name) > 0", name="full_name_nonempty"),
        CheckConstraint("length(short_name) > 0", name="short_name_nonempty"),
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    display_name: Mapped[str] = mapped_column(String(DISPLAY_NAME_MAX))
    normalized_name: Mapped[str] = mapped_column(String(DISPLAY_NAME_MAX * 2), index=True)
    chair_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("chairs.id"), index=True)
    status: Mapped[str] = mapped_column(String(10), default="active")
    merged_into_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    last_activity_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # v2 account columns. `account_kind` is NULL only for legacy v1 rows (no login); every v2
    # code path sets it, and the CHECKs below then require the matching columns. A later task
    # may tighten `account_kind` to NOT NULL once the v1 profile flow is gone (task-1.1.md).
    username: Mapped[str | None] = mapped_column(String(USERNAME_MAX))
    username_normalized: Mapped[str | None] = mapped_column(String(USERNAME_MAX), unique=True)
    account_kind: Mapped[str | None] = mapped_column(String(10))
    email: Mapped[str | None] = mapped_column(String(EMAIL_MAX))  # members only
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    sponsor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), index=True)  # guests only
    password_hash: Mapped[str | None] = mapped_column(String(255))

    chair: Mapped[Chair] = relationship(lazy="joined")

    __table_args__ = (
        CheckConstraint(_in("status", USER_STATUSES), name="status_valid"),
        CheckConstraint(
            "(status = 'merged' AND merged_into_id IS NOT NULL) OR (status <> 'merged' AND merged_into_id IS NULL)",
            name="merged_into_consistent",
        ),
        CheckConstraint("merged_into_id IS NULL OR merged_into_id <> id", name="not_merged_into_self"),
        CheckConstraint("length(display_name) > 0", name="display_name_nonempty"),
        CheckConstraint(f"account_kind IS NULL OR {_in('account_kind', ACCOUNT_KINDS)}", name="account_kind_valid"),
        CheckConstraint(
            "account_kind IS NULL OR account_kind <> 'member' OR (email IS NOT NULL AND sponsor_id IS NULL)",
            name="member_shape",
        ),
        CheckConstraint(
            "account_kind IS NULL OR account_kind <> 'guest' OR (sponsor_id IS NOT NULL AND email IS NULL)",
            name="guest_shape",
        ),
        CheckConstraint(
            "account_kind IS NULL OR (username IS NOT NULL AND username_normalized IS NOT NULL "
            "AND length(username) > 0)",
            name="username_required",
        ),
        CheckConstraint(
            "account_kind IS NULL OR (password_hash IS NOT NULL AND length(password_hash) > 0)",
            name="password_required",
        ),
        CheckConstraint("sponsor_id IS NULL OR sponsor_id <> id", name="not_own_sponsor"),
        Index(
            "uq_users_email",
            "email",
            unique=True,
            sqlite_where=text("email IS NOT NULL"),
            postgresql_where=text("email IS NOT NULL"),
        ),
    )


class AdminUser(Base):
    __tablename__ = "admin_users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64))
    username_normalized: Mapped[str] = mapped_column(String(64), unique=True)
    # NULL for group admins who sign in with their user account password (v2).
    password_hash: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(10))
    # Link to the person's user account; required for role "chair" (group admin).
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    totp_secret: Mapped[str | None] = mapped_column(String(64))
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    recovery_codes: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    user: Mapped[User | None] = relationship(lazy="selectin", foreign_keys=[user_id])

    __table_args__ = (
        CheckConstraint(_in("role", ADMIN_ROLES), name="role_valid"),
        CheckConstraint("role <> 'chair' OR user_id IS NOT NULL", name="chair_needs_user"),
    )

    @property
    def chairs(self) -> list[Chair]:
        """Chairs this admin is scoped to: a group admin's own user chair (admin_chairs is gone)."""
        return [self.user.chair] if self.user is not None else []


class Price(Base):
    __tablename__ = "prices"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    price_per_shot_cents: Mapped[int] = mapped_column(Integer)
    effective_from: Mapped[datetime] = mapped_column(UTCDateTime, unique=True)
    # NULL when set via the CLI (actor "system").
    created_by_admin_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("admin_users.id"))
    note: Mapped[str | None] = mapped_column(String(NOTE_MAX))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)

    __table_args__ = (CheckConstraint("price_per_shot_cents >= 0", name="price_nonnegative"),)


class ConsumptionEvent(Base):
    __tablename__ = "consumption_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    chair_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("chairs.id"))
    quantity: Mapped[int] = mapped_column(Integer)
    type: Mapped[str] = mapped_column(String(12))
    unit_price_cents: Mapped[int] = mapped_column(Integer)
    amount_cents: Mapped[int] = mapped_column(Integer)
    price_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("prices.id"))
    idempotency_key: Mapped[str] = mapped_column(String(80), unique=True)
    reversal_of_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("consumption_events.id"))
    # Provenance only; deliberately no FK so the session layer stays independent (PROMPT §5).
    session_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    admin_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("admin_users.id"))
    note: Mapped[str | None] = mapped_column(String(NOTE_MAX))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)

    __table_args__ = (
        CheckConstraint("quantity <> 0", name="quantity_nonzero"),
        CheckConstraint(_in("type", EVENT_TYPES), name="type_valid"),
        CheckConstraint("unit_price_cents >= 0", name="unit_price_nonnegative"),
        CheckConstraint("type <> 'single' OR quantity = 1", name="single_quantity"),
        CheckConstraint("type <> 'double' OR quantity = 2", name="double_quantity"),
        CheckConstraint(
            "type NOT IN ('single', 'double') OR amount_cents = quantity * unit_price_cents",
            name="coffee_amount",
        ),
        CheckConstraint("type NOT IN ('single', 'double') OR price_id IS NOT NULL", name="coffee_has_price"),
        CheckConstraint(
            "type <> 'reversal' OR (quantity < 0 AND reversal_of_id IS NOT NULL)", name="reversal_shape"
        ),
        CheckConstraint("type = 'reversal' OR reversal_of_id IS NULL", name="only_reversal_refs"),
        CheckConstraint("reversal_of_id IS NULL OR reversal_of_id <> id", name="not_self_reversal"),
        CheckConstraint("type <> 'adjustment' OR admin_id IS NOT NULL", name="adjustment_admin"),
        CheckConstraint(
            "NOT (quantity > 0 AND amount_cents < 0) AND NOT (quantity < 0 AND amount_cents > 0)",
            name="signs_agree",
        ),
        CheckConstraint(
            "amount_cents <> 0 OR unit_price_cents = 0 OR type IN ('adjustment', 'reversal')", name="zero_amount_allowed"
        ),
        Index(
            "uq_consumption_events_reversal_of_id",
            "reversal_of_id",
            unique=True,
            sqlite_where=text("reversal_of_id IS NOT NULL"),
            postgresql_where=text("reversal_of_id IS NOT NULL"),
        ),
        Index("ix_consumption_events_user_created", "user_id", "created_at"),
        Index("ix_consumption_events_chair_created", "chair_id", "created_at"),
        Index("ix_consumption_events_created_at", "created_at"),
        Index("ix_consumption_events_session_created", "session_id", "created_at"),
    )


class PaymentEvent(Base):
    __tablename__ = "payment_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    chair_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("chairs.id"))
    amount_cents: Mapped[int] = mapped_column(Integer)
    admin_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("admin_users.id"))
    correction_of_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("payment_events.id"))
    note: Mapped[str | None] = mapped_column(String(NOTE_MAX))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    kind: Mapped[str] = mapped_column(String(12), default="cash", server_default="cash")
    idempotency_key: Mapped[str | None] = mapped_column(String(80), unique=True)
    # The admin who physically collected the cash. "kind = cash requires a collector" is
    # enforced in the service layer (v1 payment paths do not set it yet), not by a CHECK.
    collector_admin_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("admin_users.id"))

    __table_args__ = (
        CheckConstraint("amount_cents <> 0", name="amount_nonzero"),
        CheckConstraint(_in("kind", PAYMENT_KINDS), name="kind_valid"),
        CheckConstraint("correction_of_id IS NULL OR correction_of_id <> id", name="not_self_correction"),
        Index(
            "uq_payment_events_correction_of_id",
            "correction_of_id",
            unique=True,
            sqlite_where=text("correction_of_id IS NOT NULL"),
            postgresql_where=text("correction_of_id IS NOT NULL"),
        ),
        Index("ix_payment_events_user_created", "user_id", "created_at"),
        Index("ix_payment_events_chair_created", "chair_id", "created_at"),
        Index("ix_payment_events_created_at", "created_at"),
        Index("ix_payment_events_collector_created", "collector_admin_id", "created_at"),
    )


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class PendingAction(Base):
    __tablename__ = "pending_actions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # random opaque value
    kind: Mapped[str] = mapped_column(String(10))
    nonce: Mapped[str] = mapped_column(String(80), unique=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    __table_args__ = (CheckConstraint(_in("kind", PENDING_ACTION_KINDS), name="kind_valid"),)


class AdminSession(Base):
    __tablename__ = "admin_sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    admin_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("admin_users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    stepup_until: Mapped[datetime | None] = mapped_column(UTCDateTime)
    csrf_secret: Mapped[str] = mapped_column(String(64))


class PendingRegistration(Base):
    """A registration waiting for e-mail verification (member) or sponsor approval (guest)."""

    __tablename__ = "pending_registrations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String(10))
    username: Mapped[str] = mapped_column(String(USERNAME_MAX))
    username_normalized: Mapped[str] = mapped_column(String(USERNAME_MAX), index=True)
    display_name: Mapped[str] = mapped_column(String(DISPLAY_NAME_MAX))
    chair_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("chairs.id"))
    email: Mapped[str | None] = mapped_column(String(EMAIL_MAX))  # members: the address to verify
    sponsor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), index=True)  # guests
    password_hash: Mapped[str] = mapped_column(String(255))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)  # SHA-256 of the mailed token
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    __table_args__ = (
        CheckConstraint(_in("kind", ACCOUNT_KINDS), name="kind_valid"),
        CheckConstraint(
            "kind <> 'member' OR (email IS NOT NULL AND sponsor_id IS NULL)", name="member_shape"
        ),
        CheckConstraint(
            "kind <> 'guest' OR (sponsor_id IS NOT NULL AND email IS NULL)", name="guest_shape"
        ),
        Index("ix_pending_registrations_email", "email"),
    )


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class GroupRemittance(Base):
    """Money a group admin handed to the head admin (signed; corrections are new rows)."""

    __tablename__ = "group_remittances"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    group_admin_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("admin_users.id"), index=True)
    chair_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("chairs.id"))  # chair at event time
    amount_cents: Mapped[int] = mapped_column(Integer)
    recorded_by_admin_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("admin_users.id"))  # head admin
    correction_of_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("group_remittances.id"))
    idempotency_key: Mapped[str] = mapped_column(String(80), unique=True)
    note: Mapped[str | None] = mapped_column(String(NOTE_MAX))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)

    __table_args__ = (
        CheckConstraint("amount_cents <> 0", name="amount_nonzero"),
        CheckConstraint("correction_of_id IS NULL OR correction_of_id <> id", name="not_self_correction"),
        Index(
            "uq_group_remittances_correction_of_id",
            "correction_of_id",
            unique=True,
            sqlite_where=text("correction_of_id IS NOT NULL"),
            postgresql_where=text("correction_of_id IS NOT NULL"),
        ),
        Index("ix_group_remittances_chair_created", "chair_id", "created_at"),
    )


class UsedNonce(Base):
    """Step-up confirmation nonces; inserted in the same transaction as the action they authorise."""

    __tablename__ = "used_nonces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    nonce: Mapped[str] = mapped_column(String(80), unique=True)
    consumed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)


class RateLimitEvent(Base):
    __tablename__ = "rate_limit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    bucket: Mapped[str] = mapped_column(String(32))
    key: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)

    __table_args__ = (Index("ix_rate_limit_events_bucket_key_created", "bucket", "key", "created_at"),)


class AnonymizationCounter(Base):
    """Monotonic counters for anonymized display names / usernames (e.g. name='alumni')."""

    __tablename__ = "anonymization_counters"

    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    value: Mapped[int] = mapped_column(Integer, default=0)


class UserIdentityRestore(Base):
    """Original identity after anonymizing deactivation; purged when `expires_at` passes."""

    __tablename__ = "user_identity_restores"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), unique=True)
    display_name: Mapped[str] = mapped_column(String(DISPLAY_NAME_MAX))
    username: Mapped[str] = mapped_column(String(USERNAME_MAX))
    username_normalized: Mapped[str] = mapped_column(String(USERNAME_MAX), unique=True)
    email: Mapped[str | None] = mapped_column(String(EMAIL_MAX))
    reason: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)

    __table_args__ = (
        CheckConstraint(_in("reason", IDENTITY_RESTORE_REASONS), name="reason_valid"),
        CheckConstraint("length(display_name) > 0", name="display_name_nonempty"),
        CheckConstraint("length(username) > 0", name="username_nonempty"),
        Index("ix_user_identity_restores_expires_at", "expires_at"),
    )


class AuditLog(Base):
    """Append-only; database triggers reject UPDATE and DELETE."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_type: Mapped[str] = mapped_column(String(10))
    actor_id: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    target_type: Mapped[str | None] = mapped_column(String(32))
    target_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    meta: Mapped[dict | None] = mapped_column("metadata", JSON)
    source_ip: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (
        CheckConstraint(_in("actor_type", ACTOR_TYPES), name="actor_type_valid"),
        Index("ix_audit_log_created_at", "created_at"),
        Index("ix_audit_log_target", "target_type", "target_id"),
    )


# ----- view (created in the migration, not by Alembic autogenerate) -----------------------
view_metadata = MetaData()

effective_users = Table(
    "effective_users",
    view_metadata,
    Column("id", Uuid, primary_key=True),
    Column("effective_id", Uuid),
)
# The view's SQL lives in migrations/versions/0001_initial_schema.py.

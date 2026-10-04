"""v2 schema (docs/V2-CONTRACT.md "Schema changes"): CHECKs, unique indexes, view and triggers.

Direct SQL on a migrated database, so each constraint is exercised without any service code.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.db import make_engine
from tests.conftest import alembic_config

NOW = datetime(2026, 10, 4, 12, 0)  # naive UTC, as stored by SQLite
LATER = NOW + timedelta(hours=1)


def _id() -> str:
    return uuid.uuid4().hex  # SQLAlchemy Uuid on SQLite stores 32 hex chars


@pytest.fixture
def conn(engine):
    with engine.begin() as c:
        yield c


@pytest.fixture
def chair_id(conn):
    cid = _id()
    conn.execute(text("INSERT INTO chairs (id, full_name, short_name, active, created_at) "
                      "VALUES (:i, 'Chair', :s, 1, :n)"), {"i": cid, "s": f"c{cid[:8]}", "n": NOW})
    return cid


def add_user(conn, chair_id, **kw) -> str:
    row = {"id": _id(), "display_name": "Person", "normalized_name": "person", "chair_id": chair_id,
           "status": "active", "created_at": NOW, "username": None, "username_normalized": None,
           "account_kind": None, "email": None, "sponsor_id": None, "password_hash": None, **kw}
    conn.execute(text(
        "INSERT INTO users (id, display_name, normalized_name, chair_id, status, created_at, username, "
        "username_normalized, account_kind, email, sponsor_id, password_hash) VALUES (:id, :display_name, "
        ":normalized_name, :chair_id, :status, :created_at, :username, :username_normalized, :account_kind, "
        ":email, :sponsor_id, :password_hash)"), row)
    return row["id"]


def member(conn, chair_id, name="m1", **kw) -> str:
    base = {"username": name, "username_normalized": name, "account_kind": "member",
            "email": f"{name}@tum.de", "password_hash": "h"}
    return add_user(conn, chair_id, **{**base, **kw})


def add_admin(conn, role="global", user_id=None, password_hash="h", name=None) -> str:
    row = {"id": _id(), "u": name or _id()[:8], "role": role, "user_id": user_id, "ph": password_hash, "n": NOW}
    conn.execute(text(
        "INSERT INTO admin_users (id, username, username_normalized, password_hash, role, user_id, active, "
        "totp_enabled, recovery_codes, created_at) VALUES (:id, :u, :u, :ph, :role, :user_id, 1, 0, '[]', :n)"),
        row)
    return row["id"]


def add_payment(conn, user_id, chair_id, admin_id, **kw) -> str:
    row = {"id": _id(), "user_id": user_id, "chair_id": chair_id, "admin_id": admin_id, "amount": 100,
           "n": NOW, "kind": "cash", "key": None, "collector": None, **kw}
    conn.execute(text(
        "INSERT INTO payment_events (id, user_id, chair_id, amount_cents, admin_id, created_at, kind, "
        "idempotency_key, collector_admin_id) VALUES (:id, :user_id, :chair_id, :amount, :admin_id, :n, "
        ":kind, :key, :collector)"), row)
    return row["id"]


def fails(conn, fn, *args, **kw):
    with pytest.raises(IntegrityError):
        with conn.begin_nested():
            fn(conn, *args, **kw)


# ----- users ---------------------------------------------------------------------------------
def test_valid_member_guest_and_legacy_rows(conn, chair_id):
    m = member(conn, chair_id)
    add_user(conn, chair_id, username="g1", username_normalized="g1", account_kind="guest", sponsor_id=m,
             password_hash="h")
    add_user(conn, chair_id)  # legacy v1 row: no account_kind, no username, no password


def test_member_needs_email_and_no_sponsor(conn, chair_id):
    m = member(conn, chair_id)
    fails(conn, member, chair_id, "m2", email=None)
    fails(conn, member, chair_id, "m3", sponsor_id=m)


def test_guest_needs_sponsor_and_no_email(conn, chair_id):
    m = member(conn, chair_id)
    base = {"account_kind": "guest", "password_hash": "h"}
    fails(conn, add_user, chair_id, username="g1", username_normalized="g1", **base)  # no sponsor
    fails(conn, add_user, chair_id, username="g2", username_normalized="g2", sponsor_id=m,
          email="g@tum.de", **base)


def test_password_hash_and_username_required_for_accounts(conn, chair_id):
    fails(conn, member, chair_id, "m2", password_hash=None)
    fails(conn, member, chair_id, "m3", password_hash="")
    fails(conn, member, chair_id, "m4", username=None)
    fails(conn, member, chair_id, "m5", username_normalized=None)


def test_account_kind_value_and_self_sponsor(conn, chair_id):
    fails(conn, member, chair_id, "m2", account_kind="admin")
    uid = _id()
    fails(conn, add_user, chair_id, id=uid, username="g", username_normalized="g", account_kind="guest",
          sponsor_id=uid, password_hash="h")


def test_username_normalized_unique_but_nulls_repeat(conn, chair_id):
    member(conn, chair_id, "same")
    fails(conn, member, chair_id, "other", username_normalized="same", email="x@tum.de")
    add_user(conn, chair_id)
    add_user(conn, chair_id)  # several NULL usernames are fine


def test_email_partial_unique_index(conn, chair_id):
    member(conn, chair_id, "m1", email="a@tum.de")
    fails(conn, member, chair_id, "m2", email="a@tum.de")
    m3 = member(conn, chair_id, "m3", email="b@tum.de")
    for i in range(2):  # guests have no email; NULLs never collide
        add_user(conn, chair_id, username=f"g{i}", username_normalized=f"g{i}", account_kind="guest",
                 sponsor_id=m3, password_hash="h")


# ----- admin_users / admin_sessions ------------------------------------------------------------
def test_group_admin_needs_user_link_and_user_id_unique(conn, chair_id):
    fails(conn, add_admin, role="chair")
    u = member(conn, chair_id)
    add_admin(conn, role="chair", user_id=u, password_hash=None)  # password_hash is nullable
    fails(conn, add_admin, role="global", user_id=u)  # one admin per user
    add_admin(conn, role="global")  # head admin needs no user link


def test_admin_sessions_have_stepup_until_not_totp_verified(engine):
    from sqlalchemy import inspect
    cols = {c["name"] for c in inspect(engine).get_columns("admin_sessions")}
    assert "stepup_until" in cols and "totp_verified" not in cols


# ----- payment_events -------------------------------------------------------------------------
def test_payment_kind_default_and_idempotency_key_unique(conn, chair_id):
    u, admin = member(conn, chair_id), add_admin(conn)
    p = add_payment(conn, u, chair_id, admin, collector=admin)
    assert conn.execute(text("SELECT kind FROM payment_events WHERE id=:i"), {"i": p}).scalar() == "cash"
    conn.execute(text("INSERT INTO payment_events (id, user_id, chair_id, amount_cents, admin_id, created_at) "
                      "VALUES (:i, :u, :c, 5, :a, :n)"), {"i": _id(), "u": u, "c": chair_id, "a": admin, "n": NOW})
    fails(conn, add_payment, u, chair_id, admin, kind="refund")
    add_payment(conn, u, chair_id, admin, kind="bookkeeping", key="k1")
    fails(conn, add_payment, u, chair_id, admin, key="k1")
    add_payment(conn, u, chair_id, admin)  # NULL keys repeat freely
    add_payment(conn, u, chair_id, admin)


def test_payment_collector_fk(conn, chair_id):
    u, admin = member(conn, chair_id), add_admin(conn)
    fails(conn, add_payment, u, chair_id, admin, collector=_id())


# ----- group_remittances / used_nonces / tokens / pending ------------------------------------------
def add_remittance(conn, group_admin, head, chair_id, amount=500, key=None, correction_of=None) -> str:
    row = {"id": _id(), "g": group_admin, "c": chair_id, "a": amount, "h": head, "co": correction_of,
           "k": key or _id(), "n": NOW}
    conn.execute(text(
        "INSERT INTO group_remittances (id, group_admin_id, chair_id, amount_cents, recorded_by_admin_id, "
        "correction_of_id, idempotency_key, created_at) VALUES (:id, :g, :c, :a, :h, :co, :k, :n)"), row)
    return row["id"]


def test_group_remittances_checks_and_indexes(conn, chair_id):
    u = member(conn, chair_id)
    group, head = add_admin(conn, role="chair", user_id=u), add_admin(conn)
    r = add_remittance(conn, group, head, chair_id, key="k1")
    add_remittance(conn, group, head, chair_id, amount=-500, correction_of=r)  # signed correction
    fails(conn, add_remittance, group, head, chair_id, amount=0)
    fails(conn, add_remittance, group, head, chair_id, key="k1")  # idempotency key unique
    fails(conn, add_remittance, group, head, chair_id, amount=-500, correction_of=r)  # one correction only
    fails(conn, add_remittance, group, head, chair_id, correction_of=_id())  # FK
    with pytest.raises(Exception, match="append-only"):
        conn.execute(text("UPDATE group_remittances SET amount_cents = 1"))


def test_used_nonces_unique(conn):
    ins = text("INSERT INTO used_nonces (nonce, consumed_at) VALUES (:n, :t)")
    conn.execute(ins, {"n": "abc", "t": NOW})
    fails(conn, lambda c: c.execute(ins, {"n": "abc", "t": NOW}))


def test_reset_tokens_and_pending_registrations(conn, chair_id):
    m = member(conn, chair_id)
    ins = text("INSERT INTO password_reset_tokens (id, user_id, token_hash, created_at, expires_at) "
               "VALUES (:i, :u, :t, :n, :e)")
    conn.execute(ins, {"i": _id(), "u": m, "t": "h1", "n": NOW, "e": LATER})
    fails(conn, lambda c: c.execute(ins, {"i": _id(), "u": m, "t": "h1", "n": NOW, "e": LATER}))

    def pend(c, kind, email=None, sponsor=None, token="t1"):
        c.execute(text(
            "INSERT INTO pending_registrations (id, kind, username, username_normalized, display_name, chair_id, "
            "email, sponsor_id, password_hash, token_hash, created_at, expires_at) VALUES (:i, :k, 'u', 'u', "
            "'U', :c, :e, :s, 'h', :t, :n, :x)"),
            {"i": _id(), "k": kind, "c": chair_id, "e": email, "s": sponsor, "t": token, "n": NOW, "x": LATER})

    pend(conn, "member", email="a@tum.de")
    pend(conn, "guest", sponsor=m, token="t2")
    fails(conn, pend, "member", token="t3")  # member without email
    fails(conn, pend, "member", email="a@tum.de", sponsor=m, token="t4")
    fails(conn, pend, "guest", token="t5")  # guest without sponsor
    fails(conn, pend, "guest", sponsor=m, email="a@tum.de", token="t6")
    fails(conn, pend, "member", email="b@tum.de", token="t1")  # token hash unique
    fails(conn, pend, "visitor", email="b@tum.de", token="t7")


def test_pending_actions_accept_view_site(conn):
    ins = text("INSERT INTO pending_actions (id, kind, nonce, created_at, expires_at) VALUES (:i, :k, :n, :t, :t)")
    for kind in ("single", "double", "view_site"):
        conn.execute(ins, {"i": kind, "k": kind, "n": f"n-{kind}", "t": NOW})
    fails(conn, lambda c: c.execute(ins, {"i": "x", "k": "triple", "n": "nx", "t": NOW}))


# ----- migration round trip, view, triggers ---------------------------------------------------------
def test_view_triggers_and_round_trip(tmp_path):
    url = f"sqlite:///{tmp_path / 'v2.db'}"
    cfg = alembic_config(url)
    eng = make_engine(url)
    try:
        for step in ("up", "down", "up"):
            command.upgrade(cfg, "head") if step == "up" else command.downgrade(cfg, "base")
            with eng.connect() as c:
                names = set(c.execute(text("SELECT name FROM sqlite_master WHERE type IN ('view','trigger')"))
                            .scalars())
            if step == "up":
                assert "effective_users" in names
                assert {f"{t}_no_{v}" for t in ("audit_log", "consumption_events", "payment_events", "prices",
                                                "group_remittances") for v in ("update", "delete")} <= names
            else:
                assert not names
        command.check(cfg)
    finally:
        eng.dispose()

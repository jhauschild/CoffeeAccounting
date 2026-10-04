"""Task 2.3: member registration and verification services (memory mail backend, no network)."""

from __future__ import annotations

import threading
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import func, select, update

from app.db import read_session, write_session
from app.models import (AuditLog, ConsumptionEvent, PendingAction, PendingRegistration, RateLimitEvent, User,
                        UserSession)
from app.services import mail, mail_templates, passwords, pending, registration, sessions
from app.services.errors import Conflict, InvalidInput, InvalidPassword, InvalidToken, RateLimited
from app.timeutil import ensure_utc, utcnow
from tests import factories
from tests.conftest import reload_settings

PASSWORD = "correct horse battery"


@pytest.fixture(autouse=True)
def memory_mail(monkeypatch):
    monkeypatch.setenv("MAIL_BACKEND", "memory")
    reload_settings()
    mail.clear_outbox()
    mail.reset_status()
    yield
    mail.clear_outbox()
    mail.reset_status()


def form(chair, **over):
    n = uuid.uuid4().hex[:8]
    data = dict(username=f"user-{n}", display_name="Erika Muster", chair_id=chair.id, email=f"erika.{n}@tum.de",
                password=PASSWORD, privacy_ack=True, ip="203.0.113.7")
    data.update(over)
    return data


def begin(chair, **over):
    with write_session() as w:
        return registration.begin_member(w, **form(chair, **over))


def confirm(token, **kw):
    with write_session() as w:
        return registration.confirm_member(w, token, **kw)


def count(db, model):
    db.rollback()
    return db.scalar(select(func.count()).select_from(model))


def counts(db):
    return {m.__name__: count(db, m) for m in (User, PendingRegistration, UserSession, AuditLog, RateLimitEvent,
                                                ConsumptionEvent)}


def run_threads(n, fn):
    barrier = threading.Barrier(n)
    results, errors = [], []

    def worker():
        barrier.wait()
        try:
            results.append(fn())
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    return results, errors


# ----- usernames ------------------------------------------------------------------------------
@pytest.mark.parametrize("raw,expected", [("alice", "alice"), ("  Alice.B_c-9 ", "alice.b_c-9"), ("ABC", "abc")])
def test_username_normalised(raw, expected):
    assert registration.validate_username(raw) == expected


@pytest.mark.parametrize("raw,reason", [("ab", "length"), ("a" * 33, "length"), ("", "length"), (None, "length"),
                                        ("al ice", "chars"), ("alice!", "chars"), ("müller", "chars"),
                                        ("a\nb", "chars"), ("ali/ce", "chars"), ("alice@tum.de", "chars")])
def test_username_rejected(raw, reason):
    with pytest.raises(InvalidInput) as e:
        registration.validate_username(raw)
    assert e.value.context["field"] == "username" and e.value.context["reason"] == reason


def test_username_length_bounds():
    assert registration.validate_username("abc") == "abc"
    assert registration.validate_username("a" * 32) == "a" * 32


def test_username_held_by_user_or_cli_admin_refused(db, chair):
    factories.make_member(db, username="Taken.Name", chair=chair)
    factories.make_admin(db, role="global", username="rootadmin")
    for name in ("taken.name", " TAKEN.NAME ", "RootAdmin"):
        with pytest.raises(Conflict) as e:
            registration.validate_username(name, db)
        assert e.value.context["reason"] == "username_taken"
    assert registration.validate_username("free.name", db) == "free.name"


def test_username_of_linked_group_admin_row_is_not_reserved(db, chair):
    # Only admins NOT linked to a user count as CLI admins; the linked admin's login is the account username.
    admin = factories.make_admin(db, role="chair", chairs=[chair], username="grpadmin")
    assert registration.validate_username("grpadmin", db) == "grpadmin"
    assert admin.user_id is not None


def test_begin_refuses_cli_admin_username(db, chair):
    factories.make_admin(db, role="global", username="boss")
    before = counts(db)
    with pytest.raises(Conflict):
        begin(chair, username="BOSS")
    assert counts(db) == before


# ----- email domains --------------------------------------------------------------------------
@pytest.mark.parametrize("email", ["a@tum.de", "A@TUM.DE", "a@mytum.de", "a@cit.tum.de", "a@in.CIT.tum.de",
                                   "  a@tum.de  "])
def test_allowed_domains(email):
    assert registration.validate_email(email) == email.strip().lower()


@pytest.mark.parametrize("email", ["a@tum.de.evil.com", "a@evil-tum.de", "a@eviltum.de", "a@xtum.de", "a@tum.com",
                                   "a@.tum.de", "a@tum.de.", "a@gmail.com", "a@tum.de@evil.com", "a@b@tum.de",
                                   "a@sub.tum.de.evil.com", "a@mytum.de.evil.com"])
def test_lookalike_domains_rejected(email):
    with pytest.raises(InvalidInput) as e:
        registration.validate_email(email)
    assert e.value.context["field"] == "email"


@pytest.mark.parametrize("email", ["", "no-at-sign", "a b@tum.de", "a@tum..de", "<a@tum.de>", "a\n@tum.de", None])
def test_malformed_email_rejected(email):
    with pytest.raises(InvalidInput):
        registration.validate_email(email)


def test_wildcard_does_not_match_apex_when_apex_not_listed(monkeypatch):
    monkeypatch.setenv("ALLOWED_EMAIL_DOMAINS", "*.tum.de")
    reload_settings()
    assert registration.validate_email("a@cit.tum.de")
    with pytest.raises(InvalidInput):
        registration.validate_email("a@tum.de")


def test_begin_rejects_bad_domain_without_writing(db, chair):
    before = counts(db)
    with pytest.raises(InvalidInput) as e:
        begin(chair, email="mallory@tum.de.evil.com")
    assert e.value.context["field"] == "email"
    assert counts(db) == before


# ----- other validation -----------------------------------------------------------------------
def test_display_name_controls_stripped_and_limited(db, chair):
    r = begin(chair, display_name="  Erika‮\x00 \tMuster\n ")
    db.rollback()
    row = db.scalar(select(PendingRegistration).where(PendingRegistration.id == r.pending_id))
    assert row.display_name == "Erika Muster"
    for bad in ("", "\x00‮", "x" * 61):
        with pytest.raises(InvalidInput) as e:
            begin(chair, display_name=bad)
        assert e.value.context["field"] == "display_name"


def test_inactive_or_unknown_chair_rejected(db, chair):
    chair.active = False
    db.commit()
    for cid in (chair.id, uuid.uuid4(), None):
        with pytest.raises(InvalidInput) as e:
            begin(chair, chair_id=cid)
        assert e.value.context["field"] == "chair"


def test_password_policy_and_privacy(db, chair):
    with pytest.raises(InvalidPassword):
        begin(chair, password="short")
    with pytest.raises(InvalidPassword):
        begin(chair, username="samename123", password="samename123")
    with pytest.raises(InvalidPassword):
        begin(chair, email="longlocalpart@tum.de", password="LongLocalPart")
    for ack in (False, None, "false", 0):
        with pytest.raises(InvalidInput) as e:
            begin(chair, privacy_ack=ack)
        assert e.value.context["field"] == "privacy"
    assert count(db, PendingRegistration) == 0


# ----- begin: stored data, outcome shape ------------------------------------------------------
def test_begin_stores_hashes_only(db, chair):
    r = begin(chair, username="Erika", email="Erika.Muster@TUM.de")
    assert r.already_registered is False and r.email == "erika.muster@tum.de" and len(r.token) >= 43
    db.rollback()
    row = db.scalar(select(PendingRegistration))
    assert row.kind == "member" and row.username == "erika" == row.username_normalized
    assert row.email == "erika.muster@tum.de" and row.sponsor_id is None and row.consumed_at is None
    assert row.token_hash == registration.hash_token(r.token) != r.token and len(row.token_hash) == 64
    assert row.password_hash.startswith("$argon2id$")
    assert row.expires_at - row.created_at == timedelta(hours=24)
    # Neither the raw token nor the password appears in any stored column or audit row.
    blob = " ".join(str(getattr(row, c.name)) for c in PendingRegistration.__table__.columns)
    blob += " ".join(str(a.meta) + a.action for a in db.scalars(select(AuditLog)))
    assert r.token not in blob and PASSWORD not in blob and r.token not in repr(r)
    audit = db.scalars(select(AuditLog).where(AuditLog.action == "registration.requested")).one()
    assert "erika.muster" not in str(audit.meta)  # only the domain is audited


def test_ttl_follows_settings(db, chair, monkeypatch):
    monkeypatch.setenv("VERIFICATION_TTL_HOURS", "2")
    reload_settings()
    begin(chair)
    db.rollback()
    row = db.scalar(select(PendingRegistration))
    assert row.expires_at - row.created_at == timedelta(hours=2)


def test_known_and_unknown_email_look_the_same(db, chair):
    factories.make_member(db, username="old", email="known@tum.de", chair=chair)
    known = begin(chair, email="Known@tum.de")
    unknown = begin(chair, email="unknown@tum.de")
    assert known.already_registered is True and known.token is None and known.pending_id is None
    assert unknown.already_registered is False and unknown.token
    assert type(known) is type(unknown) and known.email == "known@tum.de"
    # Known address: no pending row.
    db.rollback()
    assert [p.email for p in db.scalars(select(PendingRegistration))] == ["unknown@tum.de"]
    # Same validation errors for both (a taken username fails identically whichever the e-mail).
    for addr in ("known@tum.de", "other@tum.de"):
        with pytest.raises(Conflict):
            begin(chair, username="old", email=addr)


def test_already_registered_mail_has_no_link(db, chair):
    factories.make_member(db, username="old", email="known@tum.de", chair=chair)
    known = begin(chair, email="known@tum.de")
    msg = registration.mail_for_registration(known)
    assert msg.to == "known@tum.de"
    assert "/verify/" not in msg.body and mail.extract_links(msg) == [f"{_base()}/login"]
    assert msg.subject == mail_templates.already_registered()[0]


def _base():
    from app.config import get_settings
    return get_settings().public_base_url.rstrip("/")


def test_verification_mail_has_the_link(db, chair):
    r = begin(chair)
    msg = registration.mail_for_registration(r)
    assert msg.to == r.email and f"/verify/{r.token}" in msg.body
    assert msg.subject == mail_templates.member_verification(r.token)[0]
    assert "$argon2" not in msg.body and PASSWORD not in msg.body


def test_service_never_sends_mail(db, chair):
    begin(chair)
    begin(chair, email="x@tum.de")
    assert mail.get_outbox() == []


def test_send_after_commit_pattern(db, chair):
    r = begin(chair)
    message = registration.mail_for_registration(r)
    assert mail.send_in_background(message, r.email) is None
    out = mail.get_outbox()
    assert len(out) == 1 and out[0].to == r.email and f"/verify/{r.token}" in out[0].body


def test_known_address_counts_against_email_limit(db, chair):
    factories.make_member(db, username="old", email="known@tum.de", chair=chair)
    for i in range(5):
        begin(chair, email="known@tum.de", ip=f"198.51.100.{i + 1}")
    with pytest.raises(RateLimited):
        begin(chair, email="known@tum.de", ip="198.51.100.99")


# ----- rate limits ----------------------------------------------------------------------------
def test_per_ip_limit_ten_per_hour(db, chair):
    for _ in range(10):
        begin(chair)
    with pytest.raises(RateLimited):
        begin(chair)
    # another client is unaffected; an IPv6 client is keyed by its /64
    begin(chair, ip="198.51.100.1")
    for i in range(10):
        begin(chair, ip=f"2001:db8::{i + 1}")
    with pytest.raises(RateLimited):
        begin(chair, ip="2001:db8::ffff")


def test_per_email_limit_five_per_hour_and_window_expires(db, chair):
    for i in range(5):
        begin(chair, email="same@tum.de", ip=f"198.51.100.{i + 1}")
    with pytest.raises(RateLimited):
        begin(chair, email="SAME@tum.de", ip="198.51.100.99")
    begin(chair, email="other@tum.de", ip="198.51.100.99")
    db.execute(update(RateLimitEvent).values(created_at=utcnow() - timedelta(hours=2)))
    db.commit()
    begin(chair, email="same@tum.de", ip="198.51.100.99")


def test_rate_limit_rows_hold_no_address(db, chair):
    begin(chair, email="private.person@tum.de")
    db.rollback()
    keys = [e.key for e in db.scalars(select(RateLimitEvent).where(RateLimitEvent.bucket == "register_email"))]
    assert len(keys) == 1 and "private" not in keys[0] and "tum.de" not in keys[0]


def test_invalid_submissions_do_not_consume_limits(db, chair):
    for _ in range(12):
        with pytest.raises(InvalidInput):
            begin(chair, email="x@evil.com")
    begin(chair)  # still allowed


# ----- peek -----------------------------------------------------------------------------------
def test_peek_returns_display_data_and_writes_nothing(db, chair):
    r = begin(chair, username="Peeker", display_name="Pee Ker")
    before = counts(db)
    with read_session() as s:
        view = registration.peek_pending(s, r.token)
    assert view.username == "peeker" and view.display_name == "Pee Ker" and view.chair_short_name == "CHA"
    assert not hasattr(view, "email") and not hasattr(view, "password_hash")
    assert counts(db) == before


@pytest.mark.parametrize("kind", ["unknown", "expired", "consumed", "empty", "toolong"])
def test_peek_invalid_tokens_return_none_and_write_nothing(db, chair, kind):
    r = begin(chair)
    token = {"unknown": "nope", "empty": "", "toolong": "x" * 500}.get(kind, r.token)
    if kind == "expired":
        db.execute(update(PendingRegistration).values(expires_at=utcnow() - timedelta(seconds=1)))
        db.commit()
    if kind == "consumed":
        confirm(r.token)
    before = counts(db)
    snapshot = [(p.id, p.consumed_at, p.expires_at) for p in db.scalars(select(PendingRegistration))]
    with read_session() as s:
        assert registration.peek_pending(s, token) is None
    db.rollback()
    assert counts(db) == before
    assert snapshot == [(p.id, p.consumed_at, p.expires_at) for p in db.scalars(select(PendingRegistration))]


# ----- confirm --------------------------------------------------------------------------------
def test_confirm_creates_verified_member_and_session(db, chair):
    r = begin(chair, username="Newbie", display_name="New Bie", email="Newbie@tum.de")
    res = confirm(r.token, ip="203.0.113.9")
    assert res.created and res.event is None and res.coffee_status == "none"
    db.rollback()
    u = db.get(User, res.user.id)
    assert (u.account_kind, u.username, u.username_normalized, u.email) == ("member", "newbie", "newbie",
                                                                           "newbie@tum.de")
    assert u.display_name == "New Bie" and u.chair_id == chair.id and u.status == "active"
    assert u.verified_at is not None and u.sponsor_id is None
    assert u.password_hash == db.scalar(select(PendingRegistration.password_hash))
    assert passwords.verify_password(u.password_hash, PASSWORD)
    found = sessions.resolve_session(db, res.raw_token, touch=False)
    assert found is not None and found[1].id == u.id
    assert db.scalar(select(PendingRegistration)).consumed_at is not None
    actions = [a.action for a in db.scalars(select(AuditLog).order_by(AuditLog.id))]
    assert "user.registered" in actions and "user.verified" in actions
    blob = " ".join(str(a.meta) for a in db.scalars(select(AuditLog)))
    assert r.token not in blob and res.raw_token not in blob and PASSWORD not in blob and "argon2" not in blob


def test_confirm_replaces_old_session(db, chair, user):
    old, raw_old = sessions.create_session(db, user.id)
    db.commit()
    r = begin(chair)
    res = confirm(r.token, old_session_id=old.id)
    db.rollback()
    assert sessions.resolve_session(db, raw_old, touch=False) is None
    assert sessions.resolve_session(db, res.raw_token, touch=False) is not None


@pytest.mark.parametrize("kind", ["unknown", "expired", "consumed", "empty", "guest"])
def test_confirm_failures_are_one_typed_error(db, chair, kind):
    r = begin(chair)
    token = r.token
    if kind == "unknown":
        token = "definitely-not-a-token"
    elif kind == "empty":
        token = ""
    elif kind == "expired":
        db.execute(update(PendingRegistration).values(expires_at=utcnow() - timedelta(seconds=1)))
        db.commit()
    elif kind == "consumed":
        confirm(r.token)
    elif kind == "guest":
        sponsor = factories.make_member(db, chair=chair)
        db.execute(update(PendingRegistration).values(kind="guest", sponsor_id=sponsor.id, email=None))
        db.commit()
    users_before = count(db, User)
    with pytest.raises(InvalidToken) as e:
        confirm(token)
    assert e.value.code == "invalid_token" and str(e.value) == "verification link is invalid or expired"
    assert count(db, User) == users_before


def test_replay_creates_no_second_user(db, chair):
    r = begin(chair)
    confirm(r.token)
    with pytest.raises(InvalidToken):
        confirm(r.token)
    assert count(db, User) == 1 and count(db, UserSession) == 1


def test_expiry_boundary(db, chair):
    r = begin(chair)
    db.rollback()
    expires = ensure_utc(db.scalar(select(PendingRegistration.expires_at)))
    with pytest.raises(InvalidToken):
        confirm(r.token, now=expires)  # expired at the instant
    assert count(db, User) == 0
    confirm(r.token, now=expires - timedelta(seconds=1))
    assert count(db, User) == 1


def test_concurrent_double_confirm_creates_one_user(db, chair):
    r = begin(chair)
    results, errors = run_threads(4, lambda: confirm(r.token))
    assert len(results) == 1 and len(errors) == 3
    assert all(isinstance(e, InvalidToken) for e in errors)
    assert count(db, User) == 1 and count(db, UserSession) == 1


def test_username_race_resolved_at_confirmation(db, chair):
    a = begin(chair, username="contested", email="a@tum.de")
    b = begin(chair, username="Contested", email="b@tum.de")  # no pending row reserves a name
    first = confirm(b.token)
    with pytest.raises(Conflict) as e:
        confirm(a.token)
    assert e.value.context["reason"] == "username_taken"
    db.rollback()
    assert count(db, User) == 1 and db.get(User, first.user.id).email == "b@tum.de"
    # the loser's row stays unconsumed, no user was created
    assert db.scalar(select(PendingRegistration.consumed_at).where(PendingRegistration.id == a.pending_id)) is None
    # and a new registration of that name is refused at the form
    with pytest.raises(Conflict):
        begin(chair, username="contested")


def test_concurrent_confirms_same_username_one_wins(db, chair):
    tokens = [begin(chair, username="samename", email=f"p{i}@tum.de", ip=f"198.51.100.{i + 1}").token
              for i in range(4)]
    it = iter(tokens)
    lock = threading.Lock()

    def go():
        with lock:
            tok = next(it)
        return confirm(tok)

    results, errors = run_threads(4, go)
    assert len(results) == 1 and len(errors) == 3 and all(isinstance(e, Conflict) for e in errors)
    assert count(db, User) == 1


def test_username_taken_by_cli_admin_after_pending(db, chair):
    r = begin(chair, username="latecomer")
    factories.make_admin(db, role="global", username="latecomer")
    with pytest.raises(Conflict):
        confirm(r.token)
    assert count(db, User) == 0


def test_email_registered_meanwhile_conflicts(db, chair):
    a = begin(chair, email="dup@tum.de", username="first1")
    b = begin(chair, email="dup@tum.de", username="second1")  # a second pending row for the same address
    confirm(a.token)
    with pytest.raises(Conflict) as e:
        confirm(b.token)
    assert e.value.context["reason"] == "email_taken"
    assert count(db, User) == 1


def test_chair_deactivated_before_confirmation(db, chair):
    r = begin(chair)
    chair.active = False
    db.commit()
    with pytest.raises(InvalidInput):
        confirm(r.token)
    assert count(db, User) == 0


# ----- pending coffee -------------------------------------------------------------------------
def test_pending_coffee_recorded_exactly_once(db, chair, price):
    r = begin(chair)
    pid = pending.create_pending(db, "double", "scan-nonce-1")
    db.commit()
    res = confirm(r.token, pending_id=pid)
    assert res.coffee_status == "recorded" and res.event is not None
    assert res.event.user_id == res.user.id and res.event.idempotency_key == "scan-nonce-1"
    db.rollback()
    assert count(db, ConsumptionEvent) == 1
    assert db.get(PendingAction, pid).consumed_at is not None
    # replay of the verification link, or a second registration with the same pending id, adds nothing
    with pytest.raises(InvalidToken):
        confirm(r.token, pending_id=pid)
    r2 = begin(chair)
    res2 = confirm(r2.token, pending_id=pid)
    assert res2.event is None and res2.coffee_status == "expired"
    assert count(db, ConsumptionEvent) == 1


def test_concurrent_confirm_with_pending_coffee_records_one_coffee(db, chair, price):
    r = begin(chair)
    pid = pending.create_pending(db, "single", "scan-nonce-2")
    db.commit()
    results, errors = run_threads(3, lambda: confirm(r.token, pending_id=pid))
    assert len(results) == 1 and len(errors) == 2
    assert count(db, ConsumptionEvent) == 1 and count(db, User) == 1


def test_expired_pending_coffee_does_not_abort_registration(db, chair, price):
    r = begin(chair)
    pid = pending.create_pending(db, "single", "scan-nonce-3")
    db.execute(update(PendingAction).values(expires_at=utcnow() - timedelta(minutes=1)))
    db.commit()
    res = confirm(r.token, pending_id=pid)
    assert res.coffee_status == "expired" and res.event is None
    assert count(db, User) == 1 and count(db, ConsumptionEvent) == 0


def test_no_price_keeps_pending_coffee_and_registration(db, chair):
    r = begin(chair)
    pid = pending.create_pending(db, "single", "scan-nonce-4")
    db.commit()
    res = confirm(r.token, pending_id=pid)
    assert res.coffee_status == "no_price" and count(db, User) == 1
    db.rollback()
    assert db.get(PendingAction, pid).consumed_at is None


def test_garbage_pending_id_is_ignored(db, chair, price):
    r = begin(chair)
    res = confirm(r.token, pending_id="x" * 200)
    assert res.coffee_status == "expired" and count(db, User) == 1

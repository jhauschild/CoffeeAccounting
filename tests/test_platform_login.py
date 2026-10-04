"""Task 2.5: sign-in and password recovery services (memory mail backend, no network)."""

from __future__ import annotations

import hashlib
import re
import threading
from datetime import timedelta

import pytest
from argon2 import PasswordHasher
from sqlalchemy import func, select

from app.db import read_session, write_session
from app.models import (AdminSession, AuditLog, ConsumptionEvent, PasswordResetToken, PendingAction, RateLimitEvent,
                        User, UserSession)
from app.services import admin_auth, login, mail, onboarding, passwords, pending, ratelimit, recovery, sessions
from app.services.errors import InvalidCredentials, InvalidPassword, InvalidToken, RateLimited
from app.timeutil import utcnow
from tests import factories
from tests.conftest import reload_settings

PASSWORD = "correct horse battery"
NEW_PASSWORD = "an even better battery"
IP = "203.0.113.7"


@pytest.fixture(autouse=True)
def memory_mail(monkeypatch):
    monkeypatch.setenv("MAIL_BACKEND", "memory")
    reload_settings()
    mail.clear_outbox()
    mail.reset_status()
    yield
    mail.clear_outbox()
    mail.reset_status()


def account(db, chair, name="Alice Example", username=None, **kw):
    return factories.make_member(db, name, chair, username=username, password_hash=passwords.hash_password(PASSWORD),
                                 **kw)


def count(model, *where):
    with read_session() as db:
        return db.scalar(select(func.count()).select_from(model).where(*where))


def auth(username, password=PASSWORD, ip=IP, **kw):
    with write_session() as w:
        return login.authenticate(w, username, password, ip, **kw).id


def failed(username, password="wrong password!", ip=IP):
    """One failing attempt, committed like the route does (the error is caught inside the transaction)."""
    with write_session() as w:
        with pytest.raises(InvalidCredentials):
            login.authenticate(w, username, password, ip)


# ----- authenticate ---------------------------------------------------------------------------------------
def test_authenticate_returns_the_user_and_normalises_the_username(db, chair):
    alice = account(db, chair, username="alice.ex")
    assert auth("alice.ex") == alice.id
    assert auth("  ALICE.EX ") == alice.id
    assert count(RateLimitEvent) == 0  # a success records nothing


def test_guest_can_sign_in(db, chair):
    sponsor = account(db, chair, username="sponsor")
    guest = factories.make_guest(db, sponsor, "Gast", username="gast", password_hash=passwords.hash_password(PASSWORD))
    assert auth("gast") == guest.id


@pytest.mark.parametrize("case", ["unknown", "wrong_password", "inactive", "merged", "unverified", "legacy_v1",
                                  "empty_username", "empty_password", "overlong_password"])
def test_every_failure_is_the_same_error(db, chair, case):
    alice = account(db, chair, username="alice")
    username, password = "alice", PASSWORD
    if case == "unknown":
        username = "nobody"
    elif case == "wrong_password":
        password = "not the password"
    elif case == "inactive":
        alice.status = "inactive"
    elif case == "merged":
        target = account(db, chair, "Target", username="target")
        alice.status, alice.merged_into_id = "merged", target.id
    elif case == "unverified":
        alice.verified_at = None
    elif case == "legacy_v1":
        legacy = factories.make_user(db, "Legacy", chair)
        username = "legacy"
        legacy.username, legacy.username_normalized = "legacy", "legacy"
    elif case == "empty_username":
        username = ""
    elif case == "empty_password":
        password = ""
    elif case == "overlong_password":
        password = "x" * 5000
    db.commit()
    with write_session() as w:
        with pytest.raises(InvalidCredentials) as exc:
            login.authenticate(w, username, password, IP)
    assert str(exc.value) == "invalid username or password" and exc.value.context == {}


def test_unknown_and_unusable_accounts_burn_a_dummy_hash_check(db, chair, monkeypatch):
    gone = account(db, chair, username="gone")
    gone.status = "inactive"
    db.commit()
    calls = []
    monkeypatch.setattr(passwords, "verify_dummy", lambda password: calls.append(password))
    for name in ("nobody", "gone", ""):
        failed(name)
    assert len(calls) == 3


def test_failures_are_counted_per_username_and_ip_and_per_ip(db, chair):
    account(db, chair, username="alice")
    for _ in range(3):
        failed("alice")
    failed("nobody")
    assert count(RateLimitEvent, RateLimitEvent.bucket == "login", RateLimitEvent.key == f"alice|{IP}") == 3
    assert count(RateLimitEvent, RateLimitEvent.bucket == "login", RateLimitEvent.key == f"nobody|{IP}") == 1
    assert count(RateLimitEvent, RateLimitEvent.bucket == "login_ip", RateLimitEvent.key == IP) == 4


def test_five_failures_block_even_the_correct_password_and_record_nothing_more(db, chair):
    alice = account(db, chair, username="alice")
    for _ in range(5):
        failed("alice")
    with write_session() as w, pytest.raises(RateLimited):
        login.authenticate(w, "alice", PASSWORD, IP)
    assert count(RateLimitEvent, RateLimitEvent.bucket == "login") == 5
    # another IP, and the same IP with another username, are not blocked
    assert auth("alice", ip="198.51.100.9") == alice.id
    bob = account(db, chair, "Bob", username="bob")
    assert auth("bob") == bob.id


def test_the_window_slides(db, chair):
    alice = account(db, chair, username="alice")
    now = utcnow()
    for _ in range(5):
        with write_session() as w:
            with pytest.raises(InvalidCredentials):
                login.authenticate(w, "alice", "wrong password!", IP, now=now)
    with write_session() as w, pytest.raises(RateLimited):
        login.authenticate(w, "alice", PASSWORD, IP, now=now + timedelta(minutes=14))
    with write_session() as w:
        assert login.authenticate(w, "alice", PASSWORD, IP, now=now + timedelta(minutes=16)).id == alice.id


def test_the_per_ip_cap_applies_across_usernames_and_ipv6_prefixes(db, chair):
    limit = ratelimit.LOGIN_FAILURES_IP[1]
    for i in range(limit):
        failed(f"user{i}", ip=f"2001:db8:1:2::{i + 1:x}")
    with write_session() as w, pytest.raises(RateLimited):
        login.authenticate(w, "another", "x" * 12, "2001:db8:1:2::ffff")


def test_username_keys_are_bounded(db):
    failed("A" * 5000)
    with read_session() as r:
        keys = list(r.scalars(select(RateLimitEvent.key).where(RateLimitEvent.bucket == "login")))
    assert len(keys) == 1 and len(keys[0]) < 100


def test_an_outdated_hash_is_upgraded_on_success(db, chair):
    alice = account(db, chair, username="alice")
    old = PasswordHasher(time_cost=2, memory_cost=8, parallelism=1).hash(PASSWORD)
    alice.password_hash = old
    db.commit()
    assert passwords.needs_rehash(old)
    assert auth("alice") == alice.id
    db.expire_all()
    assert db.get(User, alice.id).password_hash != old and not passwords.needs_rehash(db.get(User, alice.id).password_hash)
    assert auth("alice") == alice.id


# ----- sign_in --------------------------------------------------------------------------------------------
def test_sign_in_issues_a_fresh_session_and_revokes_the_old_one(db, chair):
    alice = account(db, chair, username="alice")
    with write_session() as w:
        old, old_raw = sessions.create_session(w, alice.id)
    with write_session() as w:
        res = login.sign_in(w, username="alice", password=PASSWORD, ip=IP, old_session_id=old.id)
    assert res.coffee_status == onboarding.COFFEE_NONE and res.event is None and res.user.id == alice.id
    with read_session() as r:
        assert sessions.resolve_session(r, old_raw) is None
        assert sessions.resolve_session(r, res.raw_token)[1].id == alice.id
        hashed = r.scalar(select(UserSession.token_hash).where(UserSession.id == res.session.id))
    assert hashed == hashlib.sha256(res.raw_token.encode()).hexdigest() and hashed != res.raw_token


def test_sign_in_failure_creates_no_session(db, chair):
    account(db, chair, username="alice")
    with write_session() as w:
        with pytest.raises(InvalidCredentials):
            login.sign_in(w, username="alice", password="nope nope nope", ip=IP)
    assert count(UserSession) == 0


@pytest.mark.parametrize("kind,qty", [("single", 1), ("double", 2)])
def test_sign_in_records_the_pending_coffee_once(db, chair, price, kind, qty):
    alice = account(db, chair, username="alice")
    with write_session() as w:
        pid = pending.create_pending(w, kind, f"nonce-{kind}" * 3)
    with write_session() as w:
        res = login.sign_in(w, username="alice", password=PASSWORD, ip=IP, pending_id=pid)
    assert res.coffee_status == onboarding.COFFEE_RECORDED and res.event.quantity == qty
    assert res.event.user_id == alice.id and res.event.session_id == res.session.id
    with write_session() as w:  # the same cookie again, from another sign-in: used up, nothing new
        again = login.sign_in(w, username="alice", password=PASSWORD, ip=IP, pending_id=pid)
    assert again.coffee_status == onboarding.COFFEE_EXPIRED and again.event is None
    assert count(ConsumptionEvent) == 1


def test_concurrent_sign_ins_with_one_pending_cookie_record_one_coffee(db, chair, price):
    account(db, chair, username="alice")
    with write_session() as w:
        pid = pending.create_pending(w, "double", "c" * 32)
    barrier = threading.Barrier(5)
    out, errors = [], []

    def go():
        barrier.wait()
        try:
            with write_session() as w:
                out.append(login.sign_in(w, username="alice", password=PASSWORD, ip=IP, pending_id=pid).coffee_status)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=go) for _ in range(5)]
    [t.start() for t in threads]
    [t.join(30) for t in threads]
    assert not errors and out.count(onboarding.COFFEE_RECORDED) == 1 and count(ConsumptionEvent) == 1


def test_sign_in_with_a_view_site_pending_reports_it(db, chair):
    account(db, chair, username="alice")
    with write_session() as w:
        pid = pending.create_view_site_pending(w)
    with write_session() as w:
        res = login.sign_in(w, username="alice", password=PASSWORD, ip=IP, pending_id=pid)
    assert res.coffee_status == onboarding.COFFEE_VIEW_SITE and res.event is None
    assert count(PendingAction, PendingAction.consumed_at.is_not(None)) == 1


def test_sign_in_without_a_price_keeps_the_pending_coffee(db, chair):
    account(db, chair, username="alice")
    with write_session() as w:
        pid = pending.create_pending(w, "single", "n" * 32)
    with write_session() as w:
        res = login.sign_in(w, username="alice", password=PASSWORD, ip=IP, pending_id=pid)
    assert res.coffee_status == onboarding.COFFEE_NO_PRICE and count(UserSession) == 1
    assert count(PendingAction, PendingAction.consumed_at.is_(None)) == 1


def test_sign_in_is_audited_without_secrets(db, chair):
    alice = account(db, chair, username="alice")
    with write_session() as w:
        res = login.sign_in(w, username="alice", password=PASSWORD, ip=IP)
    with read_session() as r:
        row = r.scalars(select(AuditLog).where(AuditLog.action == "user.login")).one()
        actor, source_ip = row.actor_id, row.source_ip
        dump = repr([(a.action, a.meta) for a in r.scalars(select(AuditLog))])
    assert actor == str(alice.id) and source_ip == IP
    assert PASSWORD not in dump and res.raw_token not in dump


# ----- recovery: request ----------------------------------------------------------------------------------
def request(username, ip=IP, **kw):
    with write_session() as w:
        return recovery.request_reset(w, username, ip, **kw)


def token_of(outcome) -> str:
    (link,) = mail.extract_links(outcome.message)
    return link.rsplit("/", 1)[1]


def test_member_gets_a_reset_mail_naming_the_account(db, chair):
    alice = account(db, chair, username="alice", email="alice@tum.de")
    out = request("alice")
    assert out.recipient == "alice@tum.de" and out.message.to == "alice@tum.de"
    assert "alice" in out.message.body and "/reset/" in out.message.body and "1 hour" in out.message.body
    assert "sponsor" not in out.message.body.lower()
    raw = token_of(out)
    assert len(raw) >= 43
    with read_session() as r:
        row = r.scalars(select(PasswordResetToken)).one()
        user_id, token_hash, consumed, lifetime = row.user_id, row.token_hash, row.consumed_at, row.expires_at - row.created_at
    assert user_id == alice.id and token_hash == hashlib.sha256(raw.encode()).hexdigest()
    assert token_hash != raw and consumed is None
    assert timedelta(minutes=59) < lifetime <= timedelta(hours=1)
    with read_session() as r:
        dump = repr([(a.action, a.meta) for a in r.scalars(select(AuditLog))])
        keys = repr(list(r.scalars(select(RateLimitEvent.key))))
    assert raw not in dump and "alice@tum.de" not in keys  # no token, no address in audit or rate-limit rows


def test_the_validity_follows_the_setting(db, chair, monkeypatch):
    account(db, chair, username="alice")
    monkeypatch.setenv("RESET_TTL_MINUTES", "30")
    reload_settings()
    out = request("alice")
    assert "30 minutes" in out.message.body
    with read_session() as r:
        row = r.scalars(select(PasswordResetToken)).one()
        lifetime = row.expires_at - row.created_at
    assert lifetime <= timedelta(minutes=30)


def test_guest_reset_mail_goes_to_the_sponsor_and_says_so(db, chair):
    sponsor = account(db, chair, "Sponsor", username="sponsor", email="sponsor@tum.de")
    factories.make_guest(db, sponsor, "Gast", username="gast", password_hash=passwords.hash_password(PASSWORD))
    out = request("gast")
    assert out.recipient == "sponsor@tum.de"
    assert "gast" in out.message.body and "vouches for" in out.message.body


@pytest.mark.parametrize("case", ["unknown", "inactive", "merged", "unverified", "legacy_v1", "empty", "sponsor_gone"])
def test_everything_else_gives_the_same_empty_outcome(db, chair, case):
    sponsor = account(db, chair, "Sponsor", username="sponsor")
    username = "alice"
    alice = account(db, chair, username="alice")
    if case == "unknown":
        username = "nobody"
    elif case == "inactive":
        alice.status = "inactive"
    elif case == "merged":
        alice.status, alice.merged_into_id = "merged", sponsor.id
    elif case == "unverified":
        alice.verified_at = None
    elif case == "legacy_v1":
        username = "old"
        legacy = factories.make_user(db, "Legacy", chair)
        legacy.username, legacy.username_normalized = "old", "old"
    elif case == "empty":
        username = ""
    elif case == "sponsor_gone":
        sponsor.status = "inactive"
        factories.make_guest(db, sponsor, "Gast", username="gast", password_hash=passwords.hash_password(PASSWORD))
        username = "gast"
    db.commit()
    out = request(username)
    assert out == recovery.ResetOutcome() and out.message is None and out.recipient is None
    assert count(PasswordResetToken) == 0
    # the caps were counted all the same, so they say nothing about the account
    assert count(RateLimitEvent, RateLimitEvent.bucket == "reset_ip") == 1


def test_three_requests_per_username_per_hour(db, chair):
    account(db, chair, username="alice")
    now = utcnow()
    for _ in range(3):
        request("alice", now=now)
    with write_session() as w, pytest.raises(RateLimited):
        recovery.request_reset(w, "alice", "198.51.100.1", now=now + timedelta(minutes=30))
    assert count(PasswordResetToken) == 3
    assert request("alice", now=now + timedelta(minutes=61)).message is not None
    # unknown usernames are limited the same way, so the limit is no oracle
    for _ in range(3):
        request("nobody", now=now)
    with write_session() as w, pytest.raises(RateLimited):
        recovery.request_reset(w, "nobody", "198.51.100.2", now=now)


def test_ten_requests_per_ip_per_hour_even_for_unknown_users(db, chair):
    now = utcnow()
    for i in range(10):
        request(f"nobody{i}", now=now)
    with write_session() as w, pytest.raises(RateLimited):
        recovery.request_reset(w, "nobody-else", IP, now=now)
    request("nobody-else", ip="198.51.100.9", now=now)  # another IP is fine


def test_six_mails_per_recipient_per_hour_are_silently_dropped(db, chair):
    sponsor = account(db, chair, "Sponsor", username="sponsor", email="sponsor@tum.de")
    now = utcnow()
    for i in range(7):
        factories.make_guest(db, sponsor, f"Gast {i}", username=f"gast{i}",
                             password_hash=passwords.hash_password(PASSWORD))
    sent = []
    for i in range(7):
        out = request(f"gast{i}", ip=f"198.51.100.{i + 1}", now=now)  # no exception, whatever the outcome
        sent.append(out.message is not None)
    assert sent == [True] * 6 + [False]
    assert count(PasswordResetToken) == 6
    with read_session() as r:
        keys = list(r.scalars(select(RateLimitEvent.key).where(RateLimitEvent.bucket == "reset_rcpt")))
    assert len(keys) == 6 and all("sponsor" not in k and "@" not in k for k in keys)  # hashed, not the address


# ----- recovery: peek and reset ---------------------------------------------------------------------------
def issue(db, chair, username="alice", **kw):
    acct = account(db, chair, username=username, **kw)
    return acct, token_of(request(username))


def test_peek_is_read_only_and_names_the_account(db, chair):
    alice, raw = issue(db, chair)
    before = (count(PasswordResetToken), count(AuditLog), count(RateLimitEvent))
    with read_session() as r:
        view = recovery.peek_reset(r, raw)
        assert view.username == "alice" and view.display_name == "Alice Example" and not view.for_guest
        assert recovery.peek_reset(r, raw + "x") is None and recovery.peek_reset(r, "") is None
        assert recovery.peek_reset(r, None) is None and recovery.peek_reset(r, "t" * 500) is None
        assert recovery.peek_reset(r, raw, now=utcnow() + timedelta(hours=1, minutes=1)) is None
    assert (count(PasswordResetToken), count(AuditLog), count(RateLimitEvent)) == before


def test_reset_sets_the_password_consumes_the_token_and_revokes_all_sessions(db, chair):
    alice, raw = issue(db, chair)
    other = account(db, chair, "Other", username="other")
    with write_session() as w:
        _, raw1 = sessions.create_session(w, alice.id)
        _, raw2 = sessions.create_session(w, alice.id)
        _, raw_other = sessions.create_session(w, other.id)
    with write_session() as w:
        user = recovery.reset_password(w, raw, NEW_PASSWORD, ip=IP)
    assert user.id == alice.id
    with read_session() as r:
        assert sessions.resolve_session(r, raw1) is None and sessions.resolve_session(r, raw2) is None
        assert sessions.resolve_session(r, raw_other) is not None  # other accounts are untouched
        assert r.scalars(select(PasswordResetToken)).one().consumed_at is not None
        stored = r.get(User, alice.id).password_hash
        assert recovery.peek_reset(r, raw) is None
        revoked = r.scalars(select(AuditLog).where(AuditLog.action == "password.reset")).one().meta["sessions_revoked"]
        dump = repr([(a.action, a.meta) for a in r.scalars(select(AuditLog))])
    assert passwords.verify_password(stored, NEW_PASSWORD) and not passwords.verify_password(stored, PASSWORD)
    assert revoked == 2 and NEW_PASSWORD not in dump and raw not in dump
    assert auth("alice", NEW_PASSWORD) == alice.id
    with write_session() as w, pytest.raises(InvalidCredentials):
        login.authenticate(w, "alice", PASSWORD, "198.51.100.5")


def test_a_used_token_is_dead(db, chair):
    alice, raw = issue(db, chair)
    with write_session() as w:
        recovery.reset_password(w, raw, NEW_PASSWORD)
    with write_session() as w, pytest.raises(InvalidToken):
        recovery.reset_password(w, raw, "yet another battery")
    with read_session() as r:
        assert passwords.verify_password(r.get(User, alice.id).password_hash, NEW_PASSWORD)


@pytest.mark.parametrize("case", ["unknown", "garbage", "expired", "inactive_account", "unverified_account"])
def test_bad_tokens_are_one_error(db, chair, case):
    alice, raw = issue(db, chair)
    now = utcnow()
    token = raw
    if case == "unknown":
        token = "z" * 43
    elif case == "garbage":
        token = "é" * 10
    elif case == "expired":
        now = now + timedelta(hours=1, minutes=1)
    elif case == "inactive_account":
        alice.status = "inactive"
        db.commit()
    else:
        alice.verified_at = None
        db.commit()
    with write_session() as w, pytest.raises(InvalidToken):
        recovery.reset_password(w, token, NEW_PASSWORD, now=now)
    with read_session() as r:
        assert passwords.verify_password(r.get(User, alice.id).password_hash, PASSWORD)


def test_a_weak_password_does_not_burn_the_token(db, chair):
    alice, raw = issue(db, chair, email="alice.long@tum.de")
    for weak, reason in (("short", "too_short"), ("alice", "too_short"), ("x" * 129, "too_long")):
        with write_session() as w:
            with pytest.raises(InvalidPassword) as exc:
                recovery.reset_password(w, raw, weak)
            assert exc.value.context["reason"] == reason
    with write_session() as w:
        with pytest.raises(InvalidPassword) as exc:
            recovery.reset_password(w, raw, "alice.long")  # the e-mail local part (10 characters)
        assert exc.value.context["reason"] == "equals_email_local"
    with read_session() as r:
        assert r.scalars(select(PasswordResetToken)).one().consumed_at is None
    with write_session() as w:
        recovery.reset_password(w, raw, NEW_PASSWORD)


def test_a_policy_error_in_a_committing_caller_still_leaves_the_token_usable(db, chair):
    """Even if a caller commits after catching the error, nothing was consumed (validation comes first)."""
    alice, raw = issue(db, chair)
    with write_session() as w:
        with pytest.raises(InvalidPassword):
            recovery.reset_password(w, raw, "short")
    with read_session() as r:
        assert recovery.peek_reset(r, raw) is not None


def test_reset_consumes_the_other_outstanding_tokens_of_the_account(db, chair):
    alice, first = issue(db, chair)
    second = token_of(request("alice"))
    with write_session() as w:
        recovery.reset_password(w, first, NEW_PASSWORD)
    with write_session() as w, pytest.raises(InvalidToken):
        recovery.reset_password(w, second, "yet another battery")


def test_reset_revokes_the_sessions_of_a_linked_group_admin(db, chair):
    admin = factories.make_admin(db, role="chair", chairs=[chair], username="grp")
    member = admin.user
    member.password_hash = passwords.hash_password(PASSWORD)
    db.commit()
    with write_session() as w:
        out = recovery.request_reset(w, member.username, IP)
        _, admin_raw = admin_auth._new_session(w, w.get(type(admin), admin.id), now=utcnow())
        _, user_raw = sessions.create_session(w, member.id)
    raw = token_of(out)
    with write_session() as w:
        recovery.reset_password(w, raw, NEW_PASSWORD)
    with read_session() as r:
        assert sessions.resolve_session(r, user_raw) is None
        assert r.scalars(select(AdminSession)).one().revoked_at is not None
        meta = r.scalars(select(AuditLog).where(AuditLog.action == "password.reset")).one().meta
    assert meta["admin_sessions_revoked"] == 1


def test_a_guest_resets_through_the_sponsors_mail(db, chair):
    sponsor = account(db, chair, "Sponsor", username="sponsor", email="sponsor@tum.de")
    guest = factories.make_guest(db, sponsor, "Gast", username="gast", password_hash=passwords.hash_password(PASSWORD))
    raw = token_of(request("gast"))
    with read_session() as r:
        assert recovery.peek_reset(r, raw).for_guest is True
    with write_session() as w:
        assert recovery.reset_password(w, raw, NEW_PASSWORD).id == guest.id
    assert auth("gast", NEW_PASSWORD) == guest.id


def test_concurrent_resets_with_one_token_succeed_exactly_once(db, chair):
    alice, raw = issue(db, chair)
    barrier = threading.Barrier(5)
    ok, bad, errors = [], [], []

    def go(i):
        barrier.wait()
        try:
            with write_session() as w:
                recovery.reset_password(w, raw, f"battery number {i} here")
            ok.append(i)
        except InvalidToken:
            bad.append(i)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=go, args=(i,)) for i in range(5)]
    [t.start() for t in threads]
    [t.join(30) for t in threads]
    assert not errors and len(ok) == 1 and len(bad) == 4
    with read_session() as r:
        assert passwords.verify_password(r.get(User, alice.id).password_hash, f"battery number {ok[0]} here")


# ----- pending view_site ---------------------------------------------------------------------------------
def test_view_site_pending_kind(db):
    with write_session() as w:
        pid = pending.create_view_site_pending(w)
        assert pending.create_pending(w, "view_site", "fixed-nonce") == pending.create_pending(w, "view_site",
                                                                                              "fixed-nonce")
    with read_session() as r:
        assert pending.get_pending(r, pid).kind == "view_site"
    assert re.fullmatch(r"[A-Za-z0-9_-]{20,64}", pid)

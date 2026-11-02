"""Task F6: regression tests for the final-audit findings M1 (Argon2 under the SQLite write lock), L1 (reversing a
negative adjustment), L2 (empty TRUSTED_PROXY_IPS behind a proxy) and L3 (unpinned transitive dependencies)."""

from __future__ import annotations

import logging
import re
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest
import yaml
from fastapi import Request
from sqlalchemy import func, select

from app.db import read_session, write_session
from app.main import create_app
from app.models import ConsumptionEvent, RateLimitEvent, User, UserSession
from app.services import (account, ledger, login, mail, passwords, ratelimit, recovery, registration, sessions)
from app.services.errors import (InvalidCredentials, InvalidPassword, InvalidToken, NotReversible, RateLimited,
                                 ServiceError)
from app.timeutil import utcnow
from app.web import deps
from tests import factories
from tests.admin_support import fast_hasher, login_as, make_real_admin, new_client, submit  # noqa: F401
from tests.conftest import ROOT, reload_settings
from tests.test_platform_web import PROD_ENV
from tests.user_support import PASSWORD, field, make_account, sign_in

NEW_PASSWORD = "an even better battery"
IP = "203.0.113.50"


@pytest.fixture(autouse=True)
def memory_mail(monkeypatch):
    monkeypatch.setenv("MAIL_BACKEND", "memory")
    reload_settings()
    mail.clear_outbox()
    mail.reset_status()
    yield
    mail.clear_outbox()
    mail.reset_status()


def _count(model) -> int:
    with read_session() as r:
        return r.scalar(select(func.count()).select_from(model))


# ===== M1: no Argon2 while the SQLite write lock is held =====================================================
class SlowHasher:
    """Wraps the real PasswordHasher; every hash and verify sleeps (so a held lock is easy to see)."""

    def __init__(self, real, entered: threading.Event, delay: float):
        self._real, self._entered, self._delay = real, entered, delay
        self.calls = 0

    def _slow(self):
        self.calls += 1
        self._entered.set()
        time.sleep(self._delay)

    def hash(self, *a, **k):
        self._slow()
        return self._real.hash(*a, **k)

    def verify(self, *a, **k):
        self._slow()
        return self._real.verify(*a, **k)

    def check_needs_rehash(self, *a, **k):
        return self._real.check_needs_rehash(*a, **k)


def _probe_writes_during(monkeypatch, action, *, delay: float = 1.2) -> tuple[list[float], SlowHasher, object]:
    """Run `action()` in a thread with a slow hasher; while it runs, another connection keeps taking the write lock
    (BEGIN IMMEDIATE) and we time how long each attempt waits. Returns (waits, hasher, action result)."""
    entered = threading.Event()
    slow = SlowHasher(passwords.get_hasher(), entered, delay)
    monkeypatch.setattr(passwords, "get_hasher", lambda: slow)
    box: dict = {}

    def run():
        try:
            box["result"] = action()
        except Exception as exc:  # noqa: BLE001 - handed back to the test thread
            box["error"] = exc

    thread = threading.Thread(target=run)
    thread.start()
    assert entered.wait(15), "the action never hashed"
    waits: list[float] = []
    while thread.is_alive():
        started = time.monotonic()
        with write_session() as w:
            w.add(RateLimitEvent(bucket="probe", key="k", created_at=utcnow()))
        waits.append(time.monotonic() - started)
        time.sleep(0.02)
    thread.join()
    if "error" in box:
        raise box["error"]
    return waits, slow, box.get("result")


def _assert_lock_free(waits: list[float], slow: SlowHasher, *, limit: float = 0.8) -> None:
    assert slow.calls >= 1
    assert len(waits) >= 5, "the action finished before the probe could run"
    assert max(waits) < limit, f"a write waited {max(waits):.2f}s: the write lock was held while hashing"


def test_probe_detects_a_held_lock(monkeypatch, db, chair):
    """Control: the single-transaction form hashes inside the caller's write transaction, and the probe sees it."""
    make_account(db, "Alice", chair, username="alice")

    def locked():
        with write_session() as w:
            return login.sign_in(w, username="alice", password=PASSWORD, ip=IP)

    waits, slow, _ = _probe_writes_during(monkeypatch, locked)
    assert slow.calls >= 1 and max(waits) > 0.8


def test_sign_in_hashes_without_the_write_lock(monkeypatch, db, chair):
    alice = make_account(db, "Alice", chair, username="alice")
    waits, slow, result = _probe_writes_during(
        monkeypatch, lambda: login.start_sign_in(username="alice", password=PASSWORD, ip=IP))
    _assert_lock_free(waits, slow)
    assert result.user.id == alice.id and result.raw_token
    assert _count(UserSession) == 1


def test_wrong_password_and_unknown_user_hash_without_the_write_lock(monkeypatch, db, chair):
    make_account(db, "Alice", chair, username="alice")
    for name in ("alice", "nobody"):  # a wrong password, and the dummy hash of an unknown name

        def attempt(name=name):
            with pytest.raises(InvalidCredentials):
                login.start_sign_in(username=name, password="wrong password", ip=IP)

        waits, slow, _ = _probe_writes_during(monkeypatch, attempt)
        _assert_lock_free(waits, slow)
    assert _count(UserSession) == 0


def test_sign_in_over_http_hashes_without_the_write_lock(monkeypatch, client, db, chair):
    alice = make_account(db, "Alice", chair, username="alice")
    page = client.get("/login")
    data = {"csrf_token": field(page.text, "csrf_token"), "username": "alice", "password": PASSWORD}
    waits, slow, response = _probe_writes_during(
        monkeypatch, lambda: client.post("/login", data=data, follow_redirects=False))
    _assert_lock_free(waits, slow)
    assert response.status_code == 303 and "coffee_session" in response.headers["set-cookie"]
    with read_session() as r:
        assert r.scalar(select(UserSession.user_id)) == alice.id


def test_registration_hashes_without_the_write_lock(monkeypatch, client, db, chair):
    page = client.get("/register")
    data = {"csrf_token": field(page.text, "csrf_token"), "username": "erika", "display_name": "Erika Muster",
            "chair_id": str(chair.id), "email": "erika@tum.de", "password": PASSWORD, "password2": PASSWORD,
            "privacy_ack": "1"}
    waits, slow, response = _probe_writes_during(monkeypatch, lambda: client.post("/register", data=data))
    _assert_lock_free(waits, slow)
    assert response.status_code == 200 and "Check your mail" in response.text
    (message,) = mail.get_outbox()
    assert message.to == "erika@tum.de"


def test_guest_request_hashes_without_the_write_lock(monkeypatch, client, db, chair):
    sponsor = factories.make_member(db, "Sponsor", chair, username="sponsor", email="sponsor@tum.de")
    page = client.get("/register?kind=guest")
    data = {"csrf_token": field(page.text, "csrf_token"), "username": "gast", "display_name": "Gast",
            "sponsor_email": sponsor.email, "password": PASSWORD, "password2": PASSWORD, "privacy_ack": "1"}
    waits, slow, response = _probe_writes_during(monkeypatch, lambda: client.post("/register/guest", data=data))
    _assert_lock_free(waits, slow)
    assert response.status_code == 200


def test_registration_stores_the_precomputed_hash_and_still_checks_the_policy(db, chair):
    own = passwords.hash_password(PASSWORD)
    with write_session() as w:
        result = registration.begin_member(
            w, username="erika", display_name="Erika Muster", chair_id=chair.id, email="erika@tum.de",
            password=PASSWORD, privacy_ack=True, ip=IP, password_hash=own)
    with read_session() as r:
        row = r.scalar(select(registration.PendingRegistration))
        assert row.password_hash == own and result.token
    with pytest.raises(InvalidPassword):  # a hash does not bypass the policy
        with write_session() as w:
            registration.begin_member(
                w, username="erika2", display_name="Erika Muster", chair_id=chair.id, email="erika2@tum.de",
                password="short", privacy_ack=True, ip=IP, password_hash=own)


def test_password_change_hashes_without_the_write_lock(monkeypatch, db, chair):
    alice = make_account(db, "Alice", chair, username="alice")
    with write_session() as w:
        session_id = sessions.create_session(w, alice.id)[0].id
    waits, slow, _ = _probe_writes_during(
        monkeypatch, lambda: account.start_change_password(
            user_id=alice.id, session_id=session_id, current_password=PASSWORD, new_password=NEW_PASSWORD, ip=IP))
    _assert_lock_free(waits, slow)
    assert slow.calls == 2  # verify of the current password, hash of the new one
    with read_session() as r:
        assert passwords.verify_password(r.get(User, alice.id).password_hash, NEW_PASSWORD)


def test_password_reset_hashes_without_the_write_lock(monkeypatch, client, db, chair):
    alice = make_account(db, "Alice", chair, username="alice")
    with write_session() as w:
        outcome = recovery.request_reset(w, "alice", IP)
    link = re.search(r"/reset/[\w-]+", outcome.message.body).group(0)
    page = client.get(link)
    data = {"csrf_token": field(page.text, "csrf_token"), "password": NEW_PASSWORD, "password2": NEW_PASSWORD}
    waits, slow, response = _probe_writes_during(monkeypatch, lambda: client.post(link, data=data,
                                                                                  follow_redirects=False))
    _assert_lock_free(waits, slow)
    assert response.status_code == 303 and response.headers["location"] == "/login?notice=reset"
    with read_session() as r:
        assert passwords.verify_password(r.get(User, alice.id).password_hash, NEW_PASSWORD)


# ----- the state is re-checked inside the short write transaction -------------------------------------------------
def _change_after_verify(monkeypatch, change):
    """Run `change()` once, right after the Argon2 verify of the next sign-in / password change (the window in which
    no lock is held)."""
    real = passwords.verify_and_rehash
    real_verify = passwords.verify_password
    fired = []

    def after(result):
        if not fired:
            fired.append(1)
            change()
        return result

    monkeypatch.setattr(passwords, "verify_and_rehash", lambda h, p: after(real(h, p)))
    monkeypatch.setattr(passwords, "verify_password", lambda h, p: after(real_verify(h, p)))


def test_sign_in_fails_safely_when_the_password_changed_while_hashing(monkeypatch, db, chair):
    alice = make_account(db, "Alice", chair, username="alice")

    def swap_password():
        with write_session() as w:
            w.get(User, alice.id).password_hash = passwords.hash_password(NEW_PASSWORD)

    _change_after_verify(monkeypatch, swap_password)
    with pytest.raises(InvalidCredentials):
        login.start_sign_in(username="alice", password=PASSWORD, ip=IP)
    assert _count(UserSession) == 0
    with read_session() as r:  # the counted failure stays: a failed attempt costs budget
        assert ratelimit.count_hits(r, "login", f"alice|{ratelimit.ip_key(IP)}", 900) == 1
    assert login.start_sign_in(username="alice", password=NEW_PASSWORD, ip=IP).raw_token  # and the new one works


def test_sign_in_fails_safely_when_the_account_was_deactivated_while_hashing(monkeypatch, db, chair):
    alice = make_account(db, "Alice", chair, username="alice")

    def deactivate():
        with write_session() as w:
            w.get(User, alice.id).status = "inactive"

    _change_after_verify(monkeypatch, deactivate)
    with pytest.raises(InvalidCredentials):
        login.start_sign_in(username="alice", password=PASSWORD, ip=IP)
    assert _count(UserSession) == 0


def test_password_change_fails_safely_when_the_hash_changed_while_hashing(monkeypatch, db, chair):
    alice = make_account(db, "Alice", chair, username="alice")
    other = passwords.hash_password("someone else changed it")

    def swap_password():
        with write_session() as w:
            w.get(User, alice.id).password_hash = other

    _change_after_verify(monkeypatch, swap_password)
    with pytest.raises(InvalidCredentials):
        account.start_change_password(user_id=alice.id, session_id=alice.id, current_password=PASSWORD,
                                      new_password=NEW_PASSWORD, ip=IP)
    with read_session() as r:
        assert r.get(User, alice.id).password_hash == other  # nothing was overwritten
        assert ratelimit.count_hits(r, account.PASSWORD_FAILURES[0], str(alice.id), 900) == 1


def test_password_change_outcomes_match_the_single_transaction_form(db, chair):
    alice = make_account(db, "Alice", chair, username="alice")
    sid = alice.id
    bucket, limit, window = account.PASSWORD_FAILURES

    def hits():
        with read_session() as r:
            return ratelimit.count_hits(r, bucket, str(alice.id), window)

    with pytest.raises(InvalidCredentials):  # wrong current password: counted
        account.start_change_password(user_id=alice.id, session_id=sid, current_password="nope nope nope",
                                      new_password=NEW_PASSWORD)
    assert hits() == 1
    with pytest.raises(InvalidPassword):  # right current password, weak new one: not a wrong guess
        account.start_change_password(user_id=alice.id, session_id=sid, current_password=PASSWORD, new_password="x")
    assert hits() == 1
    account.start_change_password(user_id=alice.id, session_id=sid, current_password=PASSWORD,
                                  new_password=NEW_PASSWORD)
    assert hits() == 1  # the success released its own up-front count; the earlier wrong guess stays
    for _ in range(limit - 1):
        with pytest.raises(InvalidCredentials):
            account.start_change_password(user_id=alice.id, session_id=sid, current_password="nope nope nope",
                                          new_password="whatever long enough")
    with pytest.raises(RateLimited):  # the budget is spent: refused before any password check
        account.start_change_password(user_id=alice.id, session_id=sid, current_password=NEW_PASSWORD,
                                      new_password="whatever long enough")


def test_reset_fails_safely_when_the_link_was_used_meanwhile(db, chair):
    make_account(db, "Alice", chair, username="alice")
    with write_session() as w:
        outcome = recovery.request_reset(w, "alice", IP)
    token = re.search(r"/reset/([\w-]+)", outcome.message.body).group(1)
    with read_session() as r:
        recovery.check_reset(r, token, NEW_PASSWORD)  # first half: fine, writes nothing
    new_hash = passwords.hash_password(NEW_PASSWORD)
    with write_session() as w:  # somebody else uses the link in the meantime
        recovery.reset_password(w, token, "a different battery", new_hash=passwords.hash_password("a different battery"))
    with pytest.raises(InvalidToken):
        with write_session() as w:
            recovery.reset_password(w, token, NEW_PASSWORD, new_hash=new_hash)
    with pytest.raises(InvalidToken):  # the first half now refuses the used link, too
        with read_session() as r:
            recovery.check_reset(r, token, NEW_PASSWORD)
    with read_session() as r:
        assert not recovery.peek_reset(r, token)


def test_reset_check_refuses_a_weak_password_without_consuming_the_link(db, chair):
    make_account(db, "Alice", chair, username="alice")
    with write_session() as w:
        outcome = recovery.request_reset(w, "alice", IP)
    token = re.search(r"/reset/([\w-]+)", outcome.message.body).group(1)
    with pytest.raises(InvalidPassword):
        with read_session() as r:
            recovery.check_reset(r, token, "x")
    with read_session() as r:
        assert recovery.peek_reset(r, token) is not None


# ----- the per-address cap on SUCCESSFUL sign-ins -----------------------------------------------------------------
def test_successful_sign_ins_are_capped_per_address(db, chair):
    make_account(db, "Alice", chair, username="alice")
    bucket, cap, window = ratelimit.LOGIN_SUCCESS_IP
    assert (cap, window) == (60, 600)
    t0 = utcnow()
    for i in range(cap):
        login.start_sign_in(username="alice", password=PASSWORD, ip=IP, now=t0 + timedelta(seconds=i))
    with pytest.raises(RateLimited) as caught:  # correct password, but the address is over its cap
        login.start_sign_in(username="alice", password=PASSWORD, ip=IP, now=t0 + timedelta(seconds=cap))
    assert caught.value.context["bucket"] == bucket
    with pytest.raises(RateLimited):  # refused before any password check, so a wrong one is refused too
        login.start_sign_in(username="alice", password="wrong password", ip=IP, now=t0 + timedelta(seconds=cap))
    assert login.start_sign_in(username="alice", password=PASSWORD, ip="203.0.113.99",
                               now=t0 + timedelta(seconds=cap)).raw_token  # another address is not affected
    again = t0 + timedelta(seconds=window + cap)
    assert login.start_sign_in(username="alice", password=PASSWORD, ip=IP, now=again).raw_token  # window passed
    with read_session() as r:  # a limited attempt recorded nothing
        assert ratelimit.count_hits(r, "login", f"alice|{ratelimit.ip_key(IP)}", 900, now=t0 + timedelta(seconds=cap)) == 0


def test_the_cap_covers_the_single_transaction_form_and_ignores_failures(db, chair):
    make_account(db, "Alice", chair, username="alice")
    cap = ratelimit.LOGIN_SUCCESS_IP[1]
    with write_session() as w:
        for _ in range(3):  # failures do not count towards the success cap
            with pytest.raises(InvalidCredentials):
                login.authenticate(w, "alice", "wrong password", IP)
    with write_session() as w:
        for _ in range(cap):
            login.sign_in(w, username="alice", password=PASSWORD, ip=IP)
    with write_session() as w:
        with pytest.raises(RateLimited):
            login.sign_in(w, username="alice", password=PASSWORD, ip=IP)


def test_login_route_answers_429_over_the_success_cap(client, db, chair):
    make_account(db, "Alice", chair, username="alice")
    t0 = utcnow()
    with write_session() as w:
        for _ in range(ratelimit.LOGIN_SUCCESS_IP[1]):
            ratelimit.record_hit(w, ratelimit.LOGIN_SUCCESS_IP[0], ratelimit.ip_key("testclient"), t0)
    r = sign_in(client, "alice")
    assert r.status_code == 429 and "coffee_session" not in r.headers.get("set-cookie", "")


# ===== L1: reversing a negative adjustment ====================================================================
@pytest.fixture
def alice(db, chair, price):
    return factories.make_user(db, "Alice Müller", chair)


def _adjust(db, admin, user, quantity):
    event = ledger.add_adjustment(db, admin=admin, user_id=user.id, quantity=quantity, note="goodwill")
    db.commit()
    return event


def test_negative_adjustment_cannot_be_reversed_at_service_level(db, global_admin, alice):
    event = _adjust(db, global_admin, alice, -2)
    before = ledger.get_totals(db, alice.id).balance_cents
    with pytest.raises(NotReversible) as caught:
        ledger.admin_reverse_event(db, admin=global_admin, event_id=event.id, note="undo")
    db.rollback()
    assert isinstance(caught.value, ServiceError) and "opposite adjustment" in str(caught.value)
    assert caught.value.code == "not_reversible"
    assert _count(ConsumptionEvent) == 1 and ledger.get_totals(db, alice.id).balance_cents == before


def test_positive_adjustments_and_coffees_are_still_reversible(db, global_admin, alice):
    plus = _adjust(db, global_admin, alice, 2)
    coffee = factories.add_events(db, alice, ["single"])[0]
    for event in (plus, coffee):
        reversal = ledger.admin_reverse_event(db, admin=global_admin, event_id=event.id)
        assert reversal.quantity == -event.quantity
    db.commit()
    assert ledger.get_totals(db, alice.id).balance_cents == 0


def test_the_opposite_adjustment_is_the_documented_way(db, global_admin, alice):
    _adjust(db, global_admin, alice, -2)
    _adjust(db, global_admin, alice, 2)
    assert ledger.get_totals(db, alice.id).balance_cents == 0


def test_admin_page_hides_reverse_for_a_negative_adjustment_and_the_route_flashes(app, db, global_admin, alice):
    minus = _adjust(db, global_admin, alice, -2)
    plus = _adjust(db, global_admin, alice, 3)
    admin_id, _ = make_real_admin(username="boss")
    client = new_client(app)
    csrf = login_as(client, admin_id)
    page = client.get(f"/admin/users/{alice.id}").text
    assert f"/events/{minus.id}/reverse" not in page
    assert f"/events/{plus.id}/reverse" in page
    # a hand-made request (stale page, curl): a flash on the detail page, never a 500
    r = client.post(f"/admin/users/{alice.id}/events/{minus.id}/reverse",
                    data={"csrf_token": csrf, "note": "undo"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].endswith("?err=not_reversible")
    followed = client.get(r.headers["location"])
    assert followed.status_code == 200 and "negative adjustment cannot be reversed" in followed.text
    r2 = submit(client, csrf, f"/admin/users/{alice.id}/events/{minus.id}/reverse", {"note": "undo"})
    assert r2.status_code == 303 and "err=not_reversible" in r2.headers["location"]
    assert _count(ConsumptionEvent) == 2  # nothing was booked


# ===== L2: empty TRUSTED_PROXY_IPS in production ==============================================================
def _prod(monkeypatch, **extra):
    for k, v in {**PROD_ENV, "MAIL_BACKEND": "smtp", **extra}.items():
        monkeypatch.setenv(k, v)
    reload_settings()


def _req(peer: str, xff: str | None = None) -> Request:
    headers = [(b"x-forwarded-for", xff.encode())] if xff else []
    return Request({"type": "http", "method": "GET", "path": "/", "headers": headers, "client": (peer, 1234),
                    "query_string": b""})


def _warnings(caplog, needle: str) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING and needle in r.getMessage()]


def test_production_start_warns_loudly_when_trusted_proxy_ips_is_empty(monkeypatch, caplog):
    _prod(monkeypatch)
    with caplog.at_level(logging.WARNING):
        create_app()
    (message,) = _warnings(caplog, "TRUSTED_PROXY_IPS is empty")
    assert "rate-limit bucket" in message and "20 failed sign-ins" in message


def test_no_start_warning_with_a_list_or_in_development(monkeypatch, caplog):
    with caplog.at_level(logging.WARNING):
        _prod(monkeypatch, TRUSTED_PROXY_IPS="172.18.0.0/16")
        create_app()
        monkeypatch.setenv("ENVIRONMENT", "development")
        monkeypatch.setenv("TRUSTED_PROXY_IPS", "")
        monkeypatch.setenv("PUBLIC_BASE_URL", "http://localhost:8000")
        monkeypatch.setenv("MAIL_BACKEND", "memory")
        reload_settings()
        create_app()
    assert _warnings(caplog, "TRUSTED_PROXY_IPS") == []


def test_untrusted_forwarded_header_warns_once_per_hour_in_production(monkeypatch, caplog):
    _prod(monkeypatch)
    monkeypatch.setattr(deps, "_forwarded_warned_at", None)
    clock = [1000.0]
    monkeypatch.setattr(deps.time, "monotonic", lambda: clock[0])
    with caplog.at_level(logging.WARNING):
        assert deps.client_ip(_req("172.18.0.1", "6.6.6.6")) == "172.18.0.1"  # header not trusted by default
        assert deps.client_ip(_req("172.18.0.1", "7.7.7.7")) == "172.18.0.1"
        clock[0] += 3599
        deps.client_ip(_req("172.18.0.1", "7.7.7.7"))
        (message,) = _warnings(caplog, "X-Forwarded-For")
        assert "172.18.0.1" in message and "6.6.6.6" not in message and "TRUSTED_PROXY_IPS" in message
        clock[0] += 2
        deps.client_ip(_req("172.18.0.1", "7.7.7.7"))
        assert len(_warnings(caplog, "X-Forwarded-For")) == 2  # a new hour: one more


def test_no_forwarded_warning_for_a_trusted_peer_without_the_header_or_in_development(monkeypatch, caplog):
    monkeypatch.setattr(deps, "_forwarded_warned_at", None)
    with caplog.at_level(logging.WARNING):
        deps.client_ip(_req("172.18.0.1", "6.6.6.6"))  # development
        _prod(monkeypatch)
        deps.client_ip(_req("172.18.0.1"))  # production, no header
        _prod(monkeypatch, TRUSTED_PROXY_IPS="172.18.0.0/16")
        assert deps.client_ip(_req("172.18.0.1", "6.6.6.6")) == "6.6.6.6"  # trusted peer
    assert _warnings(caplog, "X-Forwarded-For") == []


def test_forwarded_headers_are_not_trusted_by_default_and_the_docs_explain_it():
    from app.config import Settings

    assert Settings(_env_file=None).trusted_proxy_ips == "" and Settings(_env_file=None).trusted_proxies == []
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    assert "TRUSTED_PROXY_IPS" not in compose["services"]["app"]["environment"]  # comes from .env, empty by default
    raw = (ROOT / "docker-compose.yml").read_text()
    assert re.search(r"^\s*#\s+TRUSTED_PROXY_IPS=172\.\d+\.0\.0/16", raw, re.M)  # commented example
    assert re.search(r"^# +networks:", raw, re.M) and "subnet: 172.28.0.0/16" in raw
    env = (ROOT / ".env.example").read_text()
    assert re.search(r"^TRUSTED_PROXY_IPS=$", env, re.M) and "ONE rate-limit bucket" in env
    readme = (ROOT / "README.md").read_text()
    assert "Symptom of an empty list behind a proxy" in readme and "one rate-limit bucket" in readme
    assert "TRUSTED_PROXY_IPS" in (ROOT / "scripts/smoke.sh").read_text()


# ===== L3: pinned, hashed lock file ============================================================================
def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_lock(text: str) -> dict[str, dict]:
    """{normalised name: {"version": str, "hashes": [sha256 hex]}} from a `--generate-hashes` file."""
    packages: dict[str, dict] = {}
    current = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?==([^\s;\\]+)", line)
        if m:
            current = packages.setdefault(_norm(m.group(1)), {"version": m.group(3), "hashes": []})
            continue
        h = re.match(r"^\s+--hash=sha256:([0-9a-f]{64})", line)
        assert h and current is not None, f"unexpected line in requirements.lock: {line!r}"
        current["hashes"].append(h.group(1))
    return packages


def _direct_requirements() -> dict[str, str]:
    out = {}
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?==(\S+)$", line)
        assert m, f"requirements.txt must pin every package with ==: {line!r}"
        out[_norm(m.group(1))] = m.group(3)
    return out


def test_every_direct_requirement_is_in_the_lock_pinned_and_hashed():
    lock = _parse_lock((ROOT / "requirements.lock").read_text())
    direct = _direct_requirements()
    assert len(direct) >= 13
    for name, version in direct.items():
        assert name in lock, f"{name} is missing from requirements.lock (regenerate it, see README)"
        assert lock[name]["version"] == version, f"{name}: lock has {lock[name]['version']}, requirements.txt {version}"
        assert lock[name]["hashes"], f"{name} has no hash in requirements.lock"


def test_the_lock_is_complete_every_package_pinned_with_hashes():
    lock = _parse_lock((ROOT / "requirements.lock").read_text())
    assert len(lock) > len(_direct_requirements())  # transitive packages are in it
    for expected in ("starlette", "pydantic", "anyio", "h11", "cffi", "markupsafe", "httptools", "uvloop"):
        assert expected in lock, f"transitive dependency {expected} is not locked"
    assert all(entry["hashes"] and len(set(entry["hashes"])) == len(entry["hashes"]) for entry in lock.values())
    text = (ROOT / "requirements.lock").read_text()
    assert "--generate-hashes" in text.splitlines()[1] + text.splitlines()[2]  # the command is recorded
    assert not re.search(r"^\s*-e |git\+|https?://", text, re.M)  # no editable or URL requirements


def test_the_dockerfile_installs_the_lock_with_hashes_on_the_tested_python():
    docker = (ROOT / "Dockerfile").read_text()
    assert re.search(r"^FROM python:3\.\d+-slim(@sha256:[0-9a-f]{64})?$", docker, re.M)
    assert "COPY requirements.lock" in docker
    assert re.search(r"pip install .*--require-hashes.* -r requirements\.lock", docker)
    assert not re.search(r"pip install[^\n]*requirements\.txt", docker)
    assert "pin the base image by digest" in docker or "@sha256" in docker
    assert "requirements.lock" not in (ROOT / ".dockerignore").read_text()  # the build context must contain it
    readme = (ROOT / "README.md").read_text()
    assert "Reproducible build" in readme and "uv pip compile" in readme and "digest" in readme

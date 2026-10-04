"""Task F4: regression tests for the M4 review findings (M1-M5, L3-L6, L8, test gaps)."""

from __future__ import annotations

import hashlib
import hmac
import logging
import uuid
from pathlib import Path

import pytest
from sqlalchemy import func, select

from app.config import Settings
from app.db import write_session
from app.models import PaymentEvent, RateLimitEvent, User
from app.services import groups, keys, ledger, mail, mail_templates, passwords, ratelimit, recovery, registration
from app.services import signing, users
from app.services.checker import check_ledger
from app.services.errors import Conflict, Forbidden, InvalidAmount, InvalidInput, RateLimited
from app.services.mail import MailError
from app.timeutil import utcnow
from tests import factories
from tests.conftest import ROOT, reload_settings
from tests.user_support import PASSWORD, field

IP = "203.0.113.50"


def codes(db):
    db.rollback()
    return {p.code for p in check_ledger(db).problems}


@pytest.fixture
def ga(db, chair, price):
    return factories.make_admin(db, role="chair", chairs=[chair], username="ga1")


@pytest.fixture
def payer(db, chair):
    return factories.make_user(db, "Payer", chair=chair)


# ----- M1: a correction keeps the chair of the payment it corrects ------------------------------------------------
def test_correction_after_a_chair_change_keeps_the_original_chair(db, ga, payer, chair, other_chair, global_admin):
    original = ledger.add_payment(db, admin=ga, user_id=payer.id, amount_cents=500)
    db.commit()
    users.update_profile(db, user_id=payer.id, chair_id=other_chair.id, actor_type="user")  # a plain member moves
    db.commit()
    correction = ledger.add_payment(db, admin=global_admin, user_id=payer.id, amount_cents=-500,
                                    correction_of_id=original.id)
    db.commit()
    assert correction.chair_id == chair.id == original.chair_id
    rollup = {row.chair_id: row for row in groups.chair_rollup(db)}
    assert (rollup[chair.id].collected_cents, rollup[chair.id].held_cents) == (0, 0)
    assert other_chair.id not in rollup or (rollup[other_chair.id].collected_cents, rollup[other_chair.id].held_cents) == (0, 0)
    assert groups.held(db, ga.id) == 0
    report = check_ledger(db)
    assert report.ok and not [n for n in report.notes if "handed over" in n]


def test_checker_flags_a_correction_with_another_chair(db, ga, payer, other_chair):
    original = ledger.add_payment(db, admin=ga, user_id=payer.id, amount_cents=500)
    db.add(PaymentEvent(user_id=payer.id, chair_id=other_chair.id, amount_cents=-500, admin_id=ga.id,
                        correction_of_id=original.id, kind="cash", collector_admin_id=ga.id, created_at=utcnow()))
    db.commit()
    assert "correction_chair" in codes(db)


# ----- M2: who may correct, and by how much -----------------------------------------------------------------------
def test_another_group_admin_of_the_chair_cannot_correct_a_held_payment(db, ga, payer, chair, global_admin):
    ga2 = factories.make_admin(db, role="chair", chairs=[chair], username="ga2")
    original = ledger.add_payment(db, admin=ga, user_id=payer.id, amount_cents=500)
    db.commit()
    for amount in (90000, -499, -500):
        with pytest.raises(Forbidden):
            ledger.add_payment(db, admin=ga2, user_id=payer.id, amount_cents=amount, correction_of_id=original.id)
    db.rollback()
    assert groups.held(db, ga.id) == 500 and groups.held(db, ga2.id) == 0
    assert db.scalar(select(func.count()).select_from(PaymentEvent)) == 1


def test_correction_must_have_the_opposite_sign_and_not_exceed_the_original(db, ga, payer, global_admin):
    original = ledger.add_payment(db, admin=ga, user_id=payer.id, amount_cents=500)
    refund = ledger.add_payment(db, admin=ga, user_id=payer.id, amount_cents=-300)
    db.commit()
    for admin, amount, target in ((global_admin, 90000, original), (global_admin, 100, original),
                                  (ga, 100, original), (global_admin, -501, original), (ga, -501, original),
                                  (global_admin, -301, refund), (global_admin, 301, refund)):
        with pytest.raises(InvalidAmount):
            ledger.add_payment(db, admin=admin, user_id=payer.id, amount_cents=amount, correction_of_id=target.id)
    db.rollback()
    partial = ledger.add_payment(db, admin=global_admin, user_id=payer.id, amount_cents=-200,
                                 correction_of_id=original.id)  # a head admin may correct part of it
    own = ledger.add_payment(db, admin=ga, user_id=payer.id, amount_cents=300, correction_of_id=refund.id)
    db.commit()  # the collector may correct their own payment
    assert partial.collector_admin_id == ga.id and own.collector_admin_id == ga.id
    assert groups.collected(db, ga.id) == 500 - 300 - 200 + 300
    assert check_ledger(db).ok


def test_bookkeeping_corrections_stay_head_admin_only(db, ga, payer, global_admin, price):
    factories.add_events(db, payer, ["double"])
    book = ledger.set_balance(db, admin=global_admin, user_id=payer.id, target_balance_cents=0, idempotency_key="k1")
    db.commit()
    with pytest.raises(Forbidden):
        ledger.add_payment(db, admin=ga, user_id=payer.id, amount_cents=-book.amount_cents,
                           correction_of_id=book.id)


def _bad_correction(db, ga, payer, **kw):
    original = ledger.add_payment(db, admin=ga, user_id=payer.id, amount_cents=500)
    row = dict(user_id=payer.id, chair_id=original.chair_id, amount_cents=-500, admin_id=ga.id,
               correction_of_id=original.id, kind="cash", collector_admin_id=ga.id, created_at=utcnow())
    row.update(kw)
    db.add(PaymentEvent(**row))
    db.commit()


@pytest.mark.parametrize("code,kw", [
    ("correction_sign", dict(amount_cents=100)),
    ("correction_amount", dict(amount_cents=-90000)),
])
def test_checker_flags_bad_correction_amounts(db, ga, payer, code, kw):
    _bad_correction(db, ga, payer, **kw)
    assert code in codes(db)


def test_checker_flags_a_correction_by_a_stranger(db, ga, payer, chair):
    ga2 = factories.make_admin(db, role="chair", chairs=[chair], username="ga2")
    _bad_correction(db, ga, payer, admin_id=ga2.id)
    assert "correction_recorder" in codes(db)


# ----- M3: a group admin cannot change chair ----------------------------------------------------------------------
def test_group_admin_cannot_change_own_chair(db, ga, chair, other_chair, global_admin):
    me = ga.user_id
    with pytest.raises(Forbidden):
        users.update_profile(db, user_id=me, chair_id=other_chair.id, actor_type="user")
    with pytest.raises(Forbidden):  # not even a head admin, while the role is active
        users.update_profile(db, user_id=me, chair_id=other_chair.id, actor_type="admin", actor_id=global_admin.id)
    db.rollback()
    assert db.get(User, me).chair_id == chair.id
    users.update_profile(db, user_id=me, display_name="New Name", chair_id=chair.id, actor_type="user")  # same chair
    ga.active = False  # role removed: the head admin may move the account
    db.flush()
    users.update_profile(db, user_id=me, chair_id=other_chair.id, actor_type="admin", actor_id=global_admin.id)
    assert db.get(User, me).chair_id == other_chair.id


def test_group_admin_cannot_change_chair_through_the_account_page(client, db, ga, chair, other_chair, login):
    login(ga.user)
    page = client.get("/account/edit").text
    data = {"csrf_token": field(page, "csrf_token"), "display_name": ga.user.display_name,
            "chair_id": str(other_chair.id)}
    r = client.post("/account/edit", data=data, follow_redirects=False)
    assert r.status_code == 403 and "cannot change" in r.text
    db.rollback()
    assert db.get(User, ga.user_id).chair_id == chair.id
    data["chair_id"] = str(chair.id)
    data["display_name"] = "Renamed"
    assert client.post("/account/edit", data=data, follow_redirects=False).status_code == 303


# ----- M4: "username taken" is throttled --------------------------------------------------------------------------
def _register(client, chair, **over):
    data = {"username": "erika", "display_name": "Erika Muster", "chair_id": str(chair.id),
            "email": "erika@tum.de", "password": PASSWORD, "password2": PASSWORD, "privacy_ack": "1"}
    data.update(over)
    data["csrf_token"] = field(client.get("/register").text, "csrf_token")
    return client.post("/register", data=data, follow_redirects=False)


@pytest.mark.parametrize("taken", ["member", "rootadmin"])
def test_username_probes_hit_a_per_ip_limit_that_survives_the_error(client, db, chair, taken):
    factories.make_member(db, "Member", chair, username="member")
    factories.make_admin(db, role="global", username="rootadmin")
    limit = ratelimit.USERNAME_PROBE[1]
    for i in range(limit):
        r = _register(client, chair, username=taken, email=f"p{i}@tum.de")
        assert r.status_code == 400 and "already taken" in r.text  # neutral answer, same for admins
    r = _register(client, chair, username=taken, email="late@tum.de")
    assert r.status_code == 429
    r = _register(client, chair, username="free-name", email="free@tum.de")
    assert r.status_code == 429  # the cap is checked first: it must not become a second oracle
    db.rollback()
    assert db.scalar(select(func.count()).select_from(RateLimitEvent)
                     .where(RateLimitEvent.bucket == "register")) == 0  # probes never used up the registration cap
    db.rollback()
    assert db.scalar(select(func.count()).select_from(RateLimitEvent)
                     .where(RateLimitEvent.bucket == ratelimit.USERNAME_PROBE[0])) == limit


def test_other_validation_errors_do_not_burn_the_probe_limit(client, db, chair):
    for i in range(15):
        assert _register(client, chair, username=f"user{i}", email="x@evil.com").status_code == 400
    db.rollback()
    assert db.scalar(select(func.count()).select_from(RateLimitEvent)) == 0
    assert _register(client, chair, username="fresh").status_code == 200


def test_service_records_the_probe_only_when_the_caller_commits(db, chair):
    factories.make_member(db, "Member", chair, username="member")
    form = dict(username="member", display_name="X Y", chair_id=chair.id, email="x@tum.de", password=PASSWORD,
                privacy_ack=True, ip=IP)
    with pytest.raises(Conflict):
        with write_session() as w:
            registration.begin_member(w, **form)  # exception out of the block: rolled back (nothing recorded)
    db.rollback()
    assert db.scalar(select(func.count()).select_from(RateLimitEvent)) == 0
    with write_session() as w:
        with pytest.raises(Conflict):
            registration.begin_member(w, **form)  # caught inside the block: committed
    db.rollback()
    assert db.scalar(select(func.count()).select_from(RateLimitEvent)
                     .where(RateLimitEvent.bucket == "username_probe")) == 1


def test_guest_form_username_probes_are_recorded_too(db, chair):
    factories.make_member(db, "Sponsor", chair, username="sabine", email="sabine@tum.de")
    form = dict(username="sabine", display_name="G G", password=PASSWORD, sponsor_email="sabine@tum.de",
                privacy_ack=True, ip=IP)
    with write_session() as w:
        with pytest.raises(Conflict):
            registration.begin_guest(w, **form)  # caught inside the block: committed
    db.rollback()
    assert db.scalar(select(func.count()).select_from(RateLimitEvent)
                     .where(RateLimitEvent.bucket == "username_probe")) == 1
    # fill the probe bucket: the guest form refuses with RateLimited before it says anything about the name
    with write_session() as w:
        for _ in range(ratelimit.USERNAME_PROBE[1] - 1):
            ratelimit.record_hit(w, "username_probe", ratelimit.ip_key(IP))
    with write_session() as w, pytest.raises(RateLimited):
        registration.begin_guest(w, **{**form, "username": "fresh-name"})


# ----- M5: no one-time token in the application log ---------------------------------------------------------------
@pytest.mark.parametrize("path,shown", [("/reset/SECRETRESETTOKEN123", "/reset/<redacted>"),
                                        ("/verify/SECRETVERIFYTOKEN456", "/verify/<redacted>")])
def test_request_log_never_contains_one_time_tokens(client, caplog, path, shown):
    caplog.set_level(logging.DEBUG)
    r = client.get(path + "?x=1")
    assert r.status_code in (400, 404)
    ours = "\n".join(rec.getMessage() for rec in caplog.records if rec.name.startswith("app"))
    assert shown in ours and "GET" in ours and str(r.status_code) in ours
    assert "SECRET" not in ours and "x=1" not in ours
    client.get("/healthz")
    assert "/healthz" in "\n".join(rec.getMessage() for rec in caplog.records if rec.name == "app.access")


def test_redact_path_only_touches_the_two_secret_prefixes():
    from app.web.accesslog import redact_path

    assert redact_path("/reset/abc") == "/reset/<redacted>" and redact_path("/verify/abc/def") == "/verify/<redacted>"
    assert redact_path("/account") == "/account" and redact_path("/resetx/abc") == "/resetx/abc"


def test_run_script_disables_the_uvicorn_access_log_and_deploy_examples_redact():
    assert "--no-access-log" in (ROOT / "scripts" / "run.sh").read_text()
    for name in ("Caddyfile", "nginx.conf"):
        text = (ROOT / "deploy" / name).read_text()
        assert "redacted" in text and "verify" in text and "reset" in text
    assert "Referer" in (ROOT / "deploy" / "Caddyfile").read_text()
    assert (ROOT / "deploy" / "README.md").exists()


# ----- L3: recipient local part -----------------------------------------------------------------------------------
@pytest.mark.parametrize("bad", ["victim%evil.example@tum.de", "a!b@tum.de", "a|b@tum.de", "a/b@tum.de",
                                 "a'b@tum.de", "a{b}@tum.de", "a=b@tum.de", "a$b@tum.de"])
def test_relay_hack_characters_in_the_local_part_are_refused(bad):
    with pytest.raises(InvalidInput):
        mail.normalize_address(bad)
    with pytest.raises(InvalidInput):
        registration.validate_email(bad)


def test_ordinary_local_parts_still_pass():
    assert registration.validate_email("Erika.Muster+tag_1-x@TUM.de") == "erika.muster+tag_1-x@tum.de"


# ----- L4: MAIL_FROM ----------------------------------------------------------------------------------------------
PROD = dict(_env_file=None, environment="production", public_base_url="https://coffee.example.org",
            secret_key="Zq3v8K1mR7tXw2pL9sD4fG6hJ0kN5bVc")


@pytest.mark.parametrize("bad", ["@", "Coffee <@>", "noreply@localhost", "coffee@intranet", "a b@example.org",
                                 "coffee@example.org, other@example.org", "<>", "x%y@example.org"])
def test_production_refuses_an_unusable_mail_from(bad):
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Settings(**PROD, mail_from=bad)


def test_production_accepts_a_real_sender():
    assert Settings(**PROD, mail_from="Coffee Ledger <coffee@example.org>").mail_from


def test_production_sender_never_falls_back_to_localhost(monkeypatch):
    class Stub:
        mail_from = "@"
        is_production = True

    monkeypatch.setattr(mail, "get_settings", lambda: Stub())
    with pytest.raises(MailError):
        mail.sender_address()
    Stub.is_production = False
    assert mail.sender_address() == "noreply@localhost"


# ----- L5: the guest's display name in the sponsor mail -----------------------------------------------------------
def test_guest_display_name_cannot_smuggle_a_link_into_the_sponsor_mail(db, chair):
    factories.make_member(db, "Sponsor", chair, username="sabine", email="sabine@tum.de")
    with write_session() as w:
        result = registration.begin_guest(w, username="evegast", display_name="Open https://evil.example/login now",
                                          password=PASSWORD, sponsor_email="sabine@tum.de", privacy_ack=True, ip=IP)
        message = registration.mail_for_guest_request(result)
    assert result.guest_display_name == "Open now"
    assert "evil.example" not in message.body and "://" in message.body  # only the real approval link remains
    assert mail.extract_links(message) == [f"{get_base()}/verify/{result.token}"]
    assert '\n"Open now"\n' in message.body


def get_base():
    from app.config import get_settings

    return get_settings().public_base_url.rstrip("/")


@pytest.mark.parametrize("name,clean", [("Eve ftp://x.y/z end", "Eve end"), ("www.evil.example hi", "hi"),
                                        ("A //evil.example/x B", "A B"), ("a:// b", "b")])
def test_urls_are_removed_from_display_names(name, clean):
    assert registration.clean_display_name(name) == clean
    assert mail_templates.neutralise_urls(name) == clean


def test_a_display_name_that_is_only_a_url_is_refused():
    with pytest.raises(InvalidInput):
        registration.clean_display_name("https://evil.example")


def test_the_template_neutralises_urls_even_for_stored_names():
    _, body = mail_templates.guest_sponsor_request(guest_display_name="Hi https://evil.example/x", guest_username="g",
                                                   token="tk")
    assert "evil.example" not in body


# ----- L6: HKDF keys for signing, CSRF and the register-email key -------------------------------------------------
def test_signing_keys_come_from_hkdf_with_one_label_per_purpose():
    assert signing._key("csrf") == keys.derive_key("signing:csrf:")
    assert signing._key("csrf") != signing._key("scan") != signing._key("register-email")
    assert signing._key("csrf", "a") != signing._key("csrf", "b")
    plain = hmac.new(b"test-secret-key-0123456789abcdef0123456789", b"coffee-ledger:csrf:", hashlib.sha256).digest()
    assert signing._key("csrf") != plain  # no longer the old plain-HMAC derivation
    want = hmac.new(keys.derive_key("signing:register-email:"), b"a@tum.de", hashlib.sha256).hexdigest()
    assert registration._email_key("a@tum.de") == want
    assert signing.mac("csrf", "m") != signing.mac("scan", "m")


def test_signed_tokens_still_round_trip_and_stay_purpose_bound():
    token = signing.sign("scan", {"k": "single"})
    assert signing.unsign("scan", token, max_age=60)["k"] == "single"
    assert signing.unsign("csrf", token, max_age=60) is None


# ----- L8: leftovers of the access gate ---------------------------------------------------------------------------
def test_no_access_code_leftovers():
    for rel in ("app/strings_admin.py", "app/services/audit.py", "static/user.css"):
        assert "access code" not in (ROOT / rel).read_text().lower(), rel
    assert "profile-name" not in (ROOT / "static" / "user.css").read_text()


# ----- recovery gap: two guests of one sponsor --------------------------------------------------------------------
def test_two_guests_of_one_sponsor_each_reset_only_their_own_account(db, chair):
    sponsor = factories.make_member(db, "Sponsor", chair, username="sabine", email="sabine@tum.de")
    old = passwords.hash_password(PASSWORD)
    g1 = factories.make_guest(db, sponsor, "Gast Eins", username="gast1", password_hash=old)
    g2 = factories.make_guest(db, sponsor, "Gast Zwei", username="gast2", password_hash=old)
    with write_session() as w:
        out1 = recovery.request_reset(w, "gast1", IP)
    with write_session() as w:
        out2 = recovery.request_reset(w, "gast2", IP)
    assert out1.recipient == out2.recipient == "sabine@tum.de"
    assert "gast1" in out1.message.body and "gast2" in out2.message.body
    t1 = mail.extract_links(out1.message)[0].rsplit("/", 1)[1]
    t2 = mail.extract_links(out2.message)[0].rsplit("/", 1)[1]
    assert t1 != t2
    with write_session() as w:
        assert recovery.reset_password(w, t1, "a brand new battery").id == g1.id
    db.rollback()
    db.refresh(g1)
    db.refresh(g2)
    assert passwords.verify_and_rehash(g1.password_hash, "a brand new battery")[0]
    assert not passwords.verify_and_rehash(g1.password_hash, PASSWORD)[0]
    assert passwords.verify_and_rehash(g2.password_hash, PASSWORD)[0]  # the other guest is untouched
    with write_session() as w:  # and its own token still works, for g2 only
        assert recovery.reset_password(w, t2, "another new battery").id == g2.id
    db.rollback()
    db.refresh(g1)
    assert passwords.verify_and_rehash(g1.password_hash, "a brand new battery")[0]

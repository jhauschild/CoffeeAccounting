"""Task 2.4: guest registration, sponsor approval, sponsor reassignment (service layer; memory mail backend)."""

from __future__ import annotations

import itertools
import threading
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app.db import read_session, write_session
from app.models import (AuditLog, ConsumptionEvent, PendingRegistration, RateLimitEvent, User, UserSession)
from app.services import mail, passwords, registration
from app.services.errors import (Conflict, Forbidden, InvalidInput, InvalidPassword, InvalidToken, NotFound,
                                 RateLimited)
from app.timeutil import ensure_utc, utcnow
from tests import factories
from tests.conftest import reload_settings

PASSWORD = "correct horse battery"
_ips = itertools.count(1)


@pytest.fixture(autouse=True)
def memory_mail(monkeypatch):
    monkeypatch.setenv("MAIL_BACKEND", "memory")
    reload_settings()
    mail.clear_outbox()
    mail.reset_status()
    yield
    mail.clear_outbox()
    mail.reset_status()


@pytest.fixture
def sponsor(db, chair):
    return factories.make_member(db, "Sabine Sponsor", chair, username="sabine", email="sabine@tum.de")


def fresh_ip():
    return f"203.0.113.{next(_ips) % 250 + 1}"


def guest_form(sponsor_email="sabine@tum.de", **over):
    n = uuid.uuid4().hex[:8]
    data = dict(username=f"guest-{n}", display_name="Gerd Gast", password=PASSWORD, sponsor_email=sponsor_email,
                privacy_ack=True, ip=fresh_ip())
    data.update(over)
    return data


def begin(sponsor_email="sabine@tum.de", **over):
    with write_session() as w:
        return registration.begin_guest(w, **guest_form(sponsor_email, **over))


def approve(token, **kw):
    with write_session() as w:
        return registration.approve_guest(w, token, **kw)


def reject(token, **kw):
    with write_session() as w:
        return registration.reject_guest(w, token, **kw)


def count(db, model):
    db.rollback()
    return db.scalar(select(func.count()).select_from(model))


def counts(db):
    return {m.__name__: count(db, m) for m in (User, PendingRegistration, UserSession, AuditLog, RateLimitEvent,
                                                ConsumptionEvent)}


def audits(db, action):
    db.rollback()
    return list(db.scalars(select(AuditLog).where(AuditLog.action == action)))


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


# ----- request and mail ---------------------------------------------------------------------------------------
def test_request_mails_the_sponsor_with_the_link(db, sponsor):
    result = begin(username="Gerd.Gast", display_name="Gerd Gast")
    assert result.token and result.pending_id
    message = registration.mail_for_guest_request(result)
    assert message.to == "sabine@tum.de"
    assert mail.send_in_background(message, result.sponsor_email) is None
    out = mail.get_outbox()
    assert len(out) == 1 and out[0].to == "sabine@tum.de"
    assert "Gerd Gast" in out[0].body and "gerd.gast" in out[0].body
    assert mail.extract_links(out[0]) == [f"http://testserver/verify/{result.token}"]
    assert "Gerd" not in out[0].subject


def test_request_stores_only_hashes_and_the_sponsor(db, sponsor):
    result = begin()
    db.rollback()
    row = db.get(PendingRegistration, result.pending_id)
    assert row.kind == "guest" and row.sponsor_id == sponsor.id and row.email is None
    assert row.chair_id == sponsor.chair_id
    assert row.token_hash == registration.hash_token(result.token) and result.token not in row.token_hash
    assert PASSWORD not in row.password_hash and passwords.verify_password(row.password_hash, PASSWORD)
    ttl = ensure_utc(row.expires_at) - ensure_utc(row.created_at)
    assert ttl == timedelta(days=7)
    assert result.token not in repr(result)
    for entry in audits(db, "registration.requested"):
        assert result.token not in str(entry.meta)


def test_sponsor_address_is_case_insensitive(db, sponsor):
    assert begin("  Sabine@TUM.de ").token


def test_same_outcome_for_member_non_member_and_unknown_domain_address(db, sponsor):
    factories.make_member(db, "Other", sponsor.chair, username="other", email="other@tum.de")
    hit = begin("sabine@tum.de")
    miss = begin("nobody@tum.de")
    sub = begin("nobody@mytum.tum.de")
    for r in (miss, sub):
        assert r.token is None and r.pending_id is None
        assert registration.mail_for_guest_request(r) is None
    assert hit.token
    # same result type and shape, same number of limiter rows per request
    assert type(hit) is type(miss) is type(sub)
    assert {f for f in hit.__dataclass_fields__} == {f for f in miss.__dataclass_fields__}
    assert count(db, PendingRegistration) == 1


def test_non_members_cause_no_row_and_no_mail(db, sponsor):
    before = counts(db)
    result = begin("nobody@tum.de")
    assert registration.mail_for_guest_request(result) is None
    after = counts(db)
    assert after["PendingRegistration"] == before["PendingRegistration"] == 0
    assert after["User"] == before["User"]
    assert mail.get_outbox() == []
    # the ip hit is counted for hit and miss alike
    assert after["RateLimitEvent"] == before["RateLimitEvent"] + 1
    begin("sabine@tum.de")
    assert counts(db)["RateLimitEvent"] == after["RateLimitEvent"] + 1


def test_a_guest_has_no_email_so_cannot_be_matched_and_never_sponsors(db, sponsor):
    guest = factories.make_guest(db, sponsor, username="gg")
    assert guest.email is None
    assert begin("gg@tum.de").token is None


def test_unverified_inactive_and_merged_members_do_not_match(db, chair):
    unverified = factories.make_member(db, "U", chair, username="unv", email="unv@tum.de")
    unverified.verified_at = None
    inactive = factories.make_member(db, "I", chair, username="ina", email="ina@tum.de")
    inactive.status = "inactive"
    db.commit()
    assert begin("unv@tum.de").token is None
    assert begin("ina@tum.de").token is None
    assert count(db, PendingRegistration) == 0


def test_non_allowed_domain_is_refused_with_a_validation_error(db, sponsor):
    with pytest.raises(InvalidInput) as exc:
        begin("sabine@gmail.com")
    assert exc.value.context["field"] == "email" and exc.value.context["reason"] == "domain"
    with pytest.raises(InvalidInput):
        begin("sabine@tum.de.evil.com")
    with pytest.raises(InvalidInput) as exc:
        begin("not an address")
    assert exc.value.context["reason"] == "format"


@pytest.mark.parametrize("over,exc", [
    (dict(username="ab"), InvalidInput), (dict(username="bad name"), InvalidInput),
    (dict(display_name="   "), InvalidInput), (dict(password="short"), InvalidPassword),
    (dict(privacy_ack=False), InvalidInput), (dict(privacy_ack=1), InvalidInput),
    (dict(username="sabine"), Conflict)])
def test_validation_like_members(db, sponsor, over, exc):
    before = counts(db)
    with pytest.raises(exc):
        begin(**over)
    assert counts(db) == before


def test_validation_errors_do_not_depend_on_the_sponsor_match(db, sponsor):
    for address in ("sabine@tum.de", "nobody@tum.de"):
        with pytest.raises(InvalidPassword):
            begin(address, password="short")
        with pytest.raises(Conflict):
            begin(address, username="sabine")


def test_password_equal_to_username_refused(db, sponsor):
    with pytest.raises(InvalidPassword):
        begin(username="gerd.gast.x1", password="gerd.gast.x1")


def test_cli_admin_username_refused(db, sponsor):
    factories.make_admin(db, "global", username="headadmin")
    with pytest.raises(Conflict):
        begin(username="HeadAdmin")


def test_pending_rows_do_not_reserve_usernames(db, sponsor):
    assert begin(username="same-name").token and begin(username="same-name").token


# ----- caps ---------------------------------------------------------------------------------------------------
def test_at_most_five_open_requests_per_sponsor_silently(db, sponsor):
    tokens = [begin().token for _ in range(5)]
    assert all(tokens)
    sixth = begin()
    assert sixth.token is None and registration.mail_for_guest_request(sixth) is None
    assert count(db, PendingRegistration) == 5
    # same page: no error, nothing sent, and the audit says why (no address, no token)
    assert len(audits(db, "registration.guest_request_limited")) == 1
    # approving or rejecting one frees a slot
    reject(tokens[0])
    assert begin().token


def test_expired_and_consumed_requests_do_not_count_towards_the_cap(db, sponsor):
    old = utcnow() - timedelta(days=8)
    for _ in range(5):
        begin(now=old)
    assert begin().token
    assert begin().token


def test_cap_is_per_sponsor(db, sponsor, chair):
    factories.make_member(db, "Second", chair, username="second", email="second@tum.de")
    for _ in range(5):
        assert begin().token
    assert begin("second@tum.de").token


def test_three_requests_per_hour_per_ip(db, sponsor):
    ip = "198.51.100.9"
    for _ in range(3):
        assert begin(ip=ip).token
    before = counts(db)
    with pytest.raises(RateLimited):
        begin(ip=ip)
    with pytest.raises(RateLimited):  # also for a non-member address: no oracle
        begin("nobody@tum.de", ip=ip)
    assert counts(db) == before
    assert begin(ip="198.51.100.10").token
    # the window slides
    assert begin(ip=ip, now=utcnow() + timedelta(hours=1, minutes=1)).token


def test_ip_limit_ignores_failed_validation(db, sponsor):
    ip = "198.51.100.20"
    for _ in range(5):
        with pytest.raises(InvalidPassword):
            begin(ip=ip, password="x")
    assert begin(ip=ip).token


def test_global_mail_cap_applies_to_sponsor_mails(db, sponsor, monkeypatch):
    monkeypatch.setenv("MAIL_MAX_PER_HOUR", "1")
    reload_settings()
    r1, r2 = begin(), begin()
    assert mail.send_in_background(registration.mail_for_guest_request(r1), r1.sponsor_email) is None
    assert mail.send_in_background(registration.mail_for_guest_request(r2), r2.sponsor_email) == "cap_exceeded"
    assert len(mail.get_outbox()) == 1


# ----- peek ---------------------------------------------------------------------------------------------------
def test_peek_shows_guest_details_and_writes_nothing(db, sponsor):
    result = begin(username="peek-me", display_name="Petra Peek")
    before = counts(db)
    with read_session() as r:
        view = registration.peek_pending(r, result.token)
        assert registration.peek_pending(r, "unknown") is None
        assert registration.peek_pending(r, None) is None
    assert (view.kind, view.username, view.display_name) == ("guest", "peek-me", "Petra Peek")
    assert view.chair_id == sponsor.chair_id and view.chair_short_name == sponsor.chair.short_name
    assert counts(db) == before


def test_peek_hides_expired_consumed_and_orphaned_requests(db, sponsor):
    expired = begin(now=utcnow() - timedelta(days=8))
    used = begin()
    reject(used.token)
    orphan = begin()
    sponsor.status = "inactive"
    db.commit()
    with read_session() as r:
        for token in (expired.token, used.token, orphan.token):
            assert registration.peek_pending(r, token) is None


def test_peek_still_serves_member_tokens(db, chair):
    with write_session() as w:
        res = registration.begin_member(w, username="mm-user", display_name="M M", chair_id=chair.id,
                                        email="mm@tum.de", password=PASSWORD, privacy_ack=True, ip=fresh_ip())
    with read_session() as r:
        assert registration.peek_pending(r, res.token).kind == "member"


def test_guest_token_does_not_work_for_confirm_member_and_vice_versa(db, sponsor, chair):
    result = begin()
    with write_session() as w:
        with pytest.raises(InvalidToken):
            registration.confirm_member(w, result.token)
    with write_session() as w:
        res = registration.begin_member(w, username="mm2-user", display_name="M M", chair_id=chair.id,
                                        email="mm2@tum.de", password=PASSWORD, privacy_ack=True, ip=fresh_ip())
    for fn in (approve, reject):
        with pytest.raises(InvalidToken):
            fn(res.token)


# ----- approve / reject ---------------------------------------------------------------------------------------
def test_no_account_and_no_sign_in_before_approval(db, sponsor):
    result = begin(username="not-yet")
    db.rollback()
    assert db.scalar(select(User).where(User.username_normalized == "not-yet")) is None
    assert count(db, UserSession) == 0


def test_approve_creates_the_guest(db, sponsor):
    result = begin(username="New.Guest", display_name="Gerd Gast")
    sessions_before = count(db, UserSession)
    guest = approve(result.token)
    db.rollback()
    row = db.scalar(select(User).where(User.username_normalized == "new.guest"))
    assert row.id == guest.id
    assert row.account_kind == "guest" and row.sponsor_id == sponsor.id and row.email is None
    assert row.verified_at is not None and row.status == "active"
    assert row.display_name == "Gerd Gast" and row.chair_id == sponsor.chair_id
    assert passwords.verify_password(row.password_hash, PASSWORD)
    assert count(db, UserSession) == sessions_before == 0  # no session is issued
    consumed = db.get(PendingRegistration, result.pending_id)
    assert consumed.consumed_at is not None
    (entry,) = audits(db, "guest.approved")
    assert entry.target_id == str(row.id) and entry.actor_id == str(sponsor.id)
    assert mail.get_outbox() == []


def test_second_approve_or_reject_after_approve_fails(db, sponsor):
    result = begin()
    approve(result.token)
    for fn in (approve, reject):
        with pytest.raises(InvalidToken):
            fn(result.token)
    assert count(db, User) == 2


def test_reject_creates_nothing(db, sponsor):
    result = begin(username="rejected-one")
    users_before = count(db, User)
    reject(result.token)
    db.rollback()
    assert count(db, User) == users_before
    assert db.get(PendingRegistration, result.pending_id).consumed_at is not None
    (entry,) = audits(db, "guest.rejected")
    assert entry.target_id == str(result.pending_id)
    with pytest.raises(InvalidToken):
        approve(result.token)
    with pytest.raises(InvalidToken):
        reject(result.token)


def test_unknown_expired_and_garbage_tokens(db, sponsor):
    expired = begin(now=utcnow() - timedelta(days=8))
    for token in ("nope", "", None, "x" * 500, expired.token):
        for fn in (approve, reject):
            with pytest.raises(InvalidToken):
                fn(token)
    assert count(db, User) == 1


def test_token_just_before_expiry_works(db, sponsor):
    result = begin(now=utcnow() - timedelta(days=7) + timedelta(minutes=5))
    assert approve(result.token).username == result.guest_username


def test_double_approve_in_threads_creates_one_guest(db, sponsor):
    result = begin(username="threaded")
    results, errors = run_threads(6, lambda: approve(result.token))
    assert len(results) == 1 and len(errors) == 5
    assert all(isinstance(e, InvalidToken) for e in errors)
    assert count(db, User) == 2


def test_username_race_between_two_requests(db, sponsor):
    a = begin(username="racer")
    b = begin(username="racer")
    approve(a.token)
    with pytest.raises(Conflict) as exc:
        approve(b.token)
    assert exc.value.context["reason"] == "username_taken"
    db.rollback()
    # the loser's request is not burnt by the failed attempt
    assert db.get(PendingRegistration, b.pending_id).consumed_at is None
    assert count(db, User) == 2


def test_username_race_in_threads(db, sponsor):
    tokens = [begin(username="racer2").token for _ in range(4)]
    it = iter(tokens)
    lock = threading.Lock()

    def go():
        with lock:
            token = next(it)
        return approve(token)

    results, errors = run_threads(4, go)
    assert len(results) == 1 and all(isinstance(e, Conflict) for e in errors) and len(errors) == 3
    assert count(db, User) == 2


def test_member_taking_the_username_first_blocks_the_guest(db, sponsor, chair):
    result = begin(username="contested")
    factories.make_member(db, "Early Bird", chair, username="contested", email="eb@tum.de")
    with pytest.raises(Conflict):
        approve(result.token)


def test_cli_admin_taking_the_username_first_blocks_the_guest(db, sponsor):
    result = begin(username="adminlike")
    factories.make_admin(db, "global", username="adminlike")
    with pytest.raises(Conflict):
        approve(result.token)


def test_sponsor_deactivated_before_approval(db, sponsor):
    result = begin(username="orphaned")
    sponsor.status = "inactive"
    db.commit()
    with pytest.raises(InvalidToken):
        approve(result.token)
    db.rollback()
    assert db.scalar(select(User).where(User.username_normalized == "orphaned")) is None
    assert db.get(PendingRegistration, result.pending_id).consumed_at is None  # rolled back, not burnt
    reject(result.token)  # the sponsor's mailbox may still reject it


def test_sponsor_demoted_to_unverified_or_merged_before_approval(db, sponsor, chair):
    other = factories.make_member(db, "Other S", chair, username="otherS", email="others@tum.de")
    r = begin("others@tum.de")
    other.status = "merged"
    other.merged_into_id = sponsor.id
    db.commit()
    with pytest.raises(InvalidToken):
        approve(r.token)


def test_chair_is_inherited_at_approval_time(db, sponsor, other_chair):
    result = begin()
    assert result.token
    sponsor.chair_id = other_chair.id
    db.commit()
    guest = approve(result.token)
    assert guest.chair_id == other_chair.id


def test_chair_is_inherited_from_the_sponsor_not_chosen(db, other_chair):
    s2 = factories.make_member(db, "S2", other_chair, username="s2", email="s2@tum.de")
    guest = approve(begin("s2@tum.de").token)
    assert guest.chair_id == other_chair.id == s2.chair_id


def test_approved_guest_can_authenticate_with_the_chosen_password(db, sponsor):
    guest = approve(begin(username="signs.in").token)
    assert passwords.verify_password(guest.password_hash, PASSWORD)
    assert not passwords.verify_password(guest.password_hash, "wrong password!!")


# ----- reassign -----------------------------------------------------------------------------------------------
def test_reassign_moves_sponsor_and_chair_and_is_audited(db, sponsor, other_chair, global_admin):
    guest = factories.make_guest(db, sponsor, username="wanderer")
    new = factories.make_member(db, "New Sponsor", other_chair, username="newsp", email="newsp@tum.de")
    with write_session() as w:
        admin = w.get(type(global_admin), global_admin.id)
        registration.reassign_sponsor(w, head_admin=admin, guest_id=guest.id, new_sponsor_id=new.id, ip="10.0.0.1")
    db.rollback()
    db.refresh(guest)
    assert guest.sponsor_id == new.id and guest.chair_id == other_chair.id
    assert guest.account_kind == "guest" and guest.email is None
    (entry,) = audits(db, "guest.sponsor_reassigned")
    assert entry.actor_type == "admin" and entry.actor_id == str(global_admin.id) and entry.target_id == str(guest.id)
    meta = entry.meta
    assert meta["from_sponsor_id"] == str(sponsor.id) and meta["to_sponsor_id"] == str(new.id)
    assert meta["from_chair_id"] == str(sponsor.chair_id) and meta["to_chair_id"] == str(other_chair.id)


def reassign(admin, guest_id, new_id):
    with write_session() as w:
        a = w.get(type(admin), admin.id)
        return registration.reassign_sponsor(w, head_admin=a, guest_id=guest_id, new_sponsor_id=new_id)


def test_reassign_refused_for_non_head_admins(db, sponsor, chair, chair_admin):
    guest = factories.make_guest(db, sponsor)
    new = factories.make_member(db, "N", chair, username="nn", email="nn@tum.de")
    with pytest.raises(Forbidden):
        reassign(chair_admin, guest.id, new.id)
    inactive = factories.make_admin(db, "global", active=False)
    with pytest.raises(Forbidden):
        reassign(inactive, guest.id, new.id)
    with write_session() as w:
        with pytest.raises(Forbidden):
            registration.reassign_sponsor(w, head_admin=None, guest_id=guest.id, new_sponsor_id=new.id)
    db.rollback()
    db.refresh(guest)
    assert guest.sponsor_id == sponsor.id and not audits(db, "guest.sponsor_reassigned")


def test_reassign_refuses_bad_sponsors(db, sponsor, chair, global_admin):
    guest = factories.make_guest(db, sponsor)
    other_guest = factories.make_guest(db, sponsor, username="og")
    inactive = factories.make_member(db, "In", chair, username="inact", email="inact@tum.de")
    inactive.status = "inactive"
    unverified = factories.make_member(db, "Un", chair, username="unver", email="unver@tum.de")
    unverified.verified_at = None
    db.commit()
    for bad in (other_guest.id, inactive.id, unverified.id, uuid.uuid4(), guest.id):
        with pytest.raises(InvalidInput) as exc:
            reassign(global_admin, guest.id, bad)
        assert exc.value.context["field"] == "sponsor"
    db.rollback()
    db.refresh(guest)
    assert guest.sponsor_id == sponsor.id


def test_reassign_target_must_be_a_guest(db, sponsor, chair, global_admin):
    new = factories.make_member(db, "N", chair, username="nn2", email="nn2@tum.de")
    with pytest.raises(InvalidInput):
        reassign(global_admin, sponsor.id, new.id)
    with pytest.raises(NotFound):
        reassign(global_admin, uuid.uuid4(), new.id)


def test_reassign_to_same_sponsor_is_a_noop(db, sponsor, global_admin):
    guest = factories.make_guest(db, sponsor)
    reassign(global_admin, guest.id, sponsor.id)
    assert not audits(db, "guest.sponsor_reassigned")


def test_reassigned_guest_recovers_through_the_new_sponsor(db, sponsor, chair, global_admin):
    guest = factories.make_guest(db, sponsor, username="recov")
    new = factories.make_member(db, "New", chair, username="newer", email="newer@tum.de")
    assert registration.recovery_address(guest, db) == "sabine@tum.de"
    reassign(global_admin, guest.id, new.id)
    db.rollback()
    db.refresh(guest)
    assert registration.recovery_address(guest, db) == "newer@tum.de"


# ----- guards -------------------------------------------------------------------------------------------------
def test_ensure_member(db, sponsor, chair):
    guest = factories.make_guest(db, sponsor)
    legacy = factories.make_user(db, "Legacy", chair)
    assert registration.ensure_member(sponsor) is sponsor
    for bad in (guest, legacy, None):
        with pytest.raises(Forbidden) as exc:
            registration.ensure_member(bad)
        assert exc.value.context["reason"] == "not_member"


def test_recovery_address_member_and_guest(db, sponsor, chair):
    g1 = factories.make_guest(db, sponsor, username="g-one")
    g2 = factories.make_guest(db, sponsor, username="g-two")
    assert registration.recovery_address(sponsor) == "sabine@tum.de"
    assert registration.recovery_address(g1) == registration.recovery_address(g2) == "sabine@tum.de"
    assert registration.recovery_address(g1, db) == "sabine@tum.de"
    assert registration.recovery_address(factories.make_user(db, "Legacy", chair)) is None


def test_recovery_address_none_when_sponsor_is_gone(db, sponsor):
    guest = factories.make_guest(db, sponsor, username="lost")
    sponsor.status = "inactive"
    db.commit()
    assert registration.recovery_address(guest, db) is None


def test_recovery_address_guest_needs_a_session(db, sponsor):
    guest = factories.make_guest(db, sponsor, username="detached")
    db.expunge(guest)
    with pytest.raises(ValueError):
        registration.recovery_address(guest)
    assert registration.recovery_address(guest, db) == "sabine@tum.de"

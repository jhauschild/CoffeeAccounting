# Task 2.4: guest registration, sponsor approval, sponsor reassignment (service layer)

Status: done. Commit "registration: guest registration, sponsor approval, reassignment (task 2.4)".
Full suite (e2e excluded): 1234 passed, 0 failed, 0 errors (baseline 1179). 55 new tests in `tests/test_platform_guest.py`; memory mail backend.

## What changed (only `app/services/registration.py`, member behaviour untouched)
- `begin_guest(db, *, username, display_name, password, sponsor_email, privacy_ack, ip, now=None) -> GuestRequestResult(sponsor_email, token, pending_id, guest_display_name, guest_username)`; `mail_for_guest_request(result) -> MailMessage | None` (None when `token is None`; message goes to the SPONSOR). Route pattern: commit, then `if message: background_tasks.add_task(send_in_background, message, result.sponsor_email)`; always show the same neutral page.
- `peek_pending` now also serves guest tokens (`PendingView.kind == "guest"`; chair = sponsor's chair at request time). Returns None for expired/consumed/unknown and for a guest token whose sponsor is no longer an active verified member. No writes.
- `approve_guest(db, raw_token, *, ip=None, now=None) -> User` (no session issued), `reject_guest(db, raw_token, *, ip=None, now=None)`. `InvalidToken` for unknown/expired/consumed/wrong-kind (a member token is never accepted here, a guest token never by `confirm_member`). Approve also raises `InvalidToken(reason="sponsor_inactive")`, `Conflict(reason="username_taken")`.
- `reassign_sponsor(db, *, head_admin, guest_id, new_sponsor_id, ip=None, now=None) -> User` (audit `guest.sponsor_reassigned` with from/to sponsor and chair).
- `ensure_member(user) -> user` (`Forbidden`, `context["reason"] == "not_member"` for guest, legacy profile, None); `recovery_address(user, db=None) -> str | None`.
- Constants: `GUEST_REQUEST_IP = ("guest_request", 3, 3600)`, `MAX_OPEN_REQUESTS_PER_SPONSOR = 5`.

## Decisions
- Sponsor match: `users.email == address AND account_kind member AND verified_at set AND status active`. Guests have no email, so they can never match.
- Neutral outcome: a member address, a non-member address, a sponsor at 5 open requests all return a normal result; only `token`/`pending_id` differ (internal). The only errors are validation errors, including the non-allowed domain (`InvalidInput field=email reason=domain`), and the per-IP `RateLimited` (raised for member and non-member addresses alike, before validation, like `begin_member`). The IP hit is counted for matches and non-matches. A full sponsor writes an audit row `registration.guest_request_limited` (sponsor id, guest username; no address/token).
- Open request = kind guest, unconsumed, unexpired. Pending rows never reserve a username; approval decides.
- Password policy for guests runs with no email (guests have none; the sponsor's address is not used).
- Approve order: checks (usable token, sponsor active, username free) then atomic consume then `create_account` in a savepoint. Failures raise out of the caller's transaction, so the token is not burnt. Chair = sponsor's chair at approval time (`InvalidInput` if that chair is deactivated).
- Audit: approve/reject use `actor_type="user"`, `actor_id=sponsor.id` (the link is the sponsor's capability; the sponsor is not logged in). Reject works even if the sponsor was deactivated meanwhile.
- No guest-facing mail on approve/reject (a guest has no address); templates `guest_approved`/`guest_rejected` are unused here.
- `reassign_sponsor`: head admin = `authz.require_global` (inactive or group admin gives `Forbidden`); target must be a guest (`InvalidInput field=guest`), new sponsor an active verified member (`InvalidInput field=sponsor`; guests, inactive, unverified, unknown, merged all refused); guest's chair becomes the new sponsor's chair; same sponsor again is a no-op (no audit). Sessions are not touched.
- `recovery_address`: member gives own email; guest gives the sponsor's email, or None if the sponsor is not an active verified member (head admin must reassign); legacy profile None. Guest without `db` uses `object_session`, else `ValueError`.

## Later tasks must know
- 2.5 recovery: use `recovery_address(user, db)`; send with `send_in_background(message, recovery_address)` so the per-recipient cap protects sponsors; `password_reset(..., for_guest=True)` for guests.
- 3.x routes: `GET /verify/{token}` = `peek_pending` (kind decides member page vs Approve/Reject page); guest POSTs are separate actions (approve / reject); after approve show "you can sign in now" to the SPONSOR (no session, no cookie). Map `InvalidToken` to the one invalid-link page, `Conflict` to "username taken".
- 4.3 must call `registration.ensure_member(user)` before linking an admin account to a user.
- 4.x admin UI for reassign calls `reassign_sponsor` inside `write_session` with the head admin row.
- `purge-expired` still does not delete old `pending_registrations`.

## Known-broken
- None.

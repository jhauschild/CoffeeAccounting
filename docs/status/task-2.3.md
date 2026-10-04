# Task 2.3: member registration and verification (service layer)

Status: done. Commit "registration: member registration and verification services (task 2.3)".
Full suite (e2e excluded): 1121 passed, 0 failed, 0 errors (baseline 1036). 85 new tests in `tests/test_platform_registration.py`; memory mail backend, no network.

## What changed
- `app/services/registration.py` (new): `validate_username(raw, db=None)`, `validate_email`, `domain_allowed`, `clean_display_name`, `begin_member`, `mail_for_registration`, `peek_pending`, `confirm_member`, `hash_token`; result types `RegistrationResult(email, already_registered, token (repr hidden), pending_id)` and `PendingView`.
- `app/services/errors.py`: new `InvalidToken` (code `invalid_token`), one error for unknown/expired/consumed/wrong-kind tokens. 2.4 and 2.5 should reuse it.
- `app/services/users.py`: `create_account(db, *, kind, username, username_normalized, display_name, chair_id, password_hash, email=None, sponsor_id=None, verified_at=None, now=None)` (2.4 uses it for guests).
- `app/services/onboarding.py`: `start_session_and_record(db, user, *, pending_id, old_session_id, now) -> OnboardResult` (new session, revoke the old one, consume + record the pending coffee exactly as `register_and_start_session`). 2.5 login should use it too. v1 gate/profile code untouched.

## Decisions
- Username: stored lower-case (strip + casefold), 3-32 chars of `a-z 0-9 . _ -`. Refused when `users.username_normalized` or a CLI admin (admin row with `user_id IS NULL`) holds it. Pending rows do not reserve names; confirmation decides (loser gets `Conflict`, `context["reason"] == "username_taken"`). `InvalidInput.context["field"]` is one of username, display_name, chair, email, privacy (`reason` where useful: length, chars, format, domain); password errors are `InvalidPassword`.
- Email: `mail.normalize_address` then domain check (`tum.de` exact, `*.tum.de` subdomains only, case-insensitive). `privacy_ack` must be `True` (not just truthy).
- Rate limits (hourly): 10 per client IP (`ratelimit.REGISTRATION`, IPv6 by /64), 5 per email (bucket `register_email`, key = HMAC of the lower-cased address, no address stored). They are counted in the caller's transaction, so a request that fails validation (exception, rollback) does not consume them. The already-registered path counts like any other.
- Known email: no pending row, `already_registered=True`, `token=None`; password is still hashed (timing). Username/validation errors are raised before the email lookup, so they never differ by email state. Audit rows: `registration.requested` (domain only, no address, no token), `registration.duplicate_email`, `user.registered`, `user.verified`.
- `confirm_member` checks conflicts (username, email taken) BEFORE the atomic `UPDATE ... WHERE consumed_at IS NULL AND expires_at > now`, so a `Conflict` never burns the token even if a caller commits; failures raise out of the caller's transaction anyway. Pending coffee failures (expired, no price) never abort the registration; see `OnboardResult.coffee_status`.
- Mail call pattern: `message = mail_for_registration(result)`; after the commit `background_tasks.add_task(send_in_background, message, result.email)`. Always show the same page.

## Later tasks must know
- Routes (3.1): `/verify/{token}` GET = `peek_pending` in a read session (writes nothing); POST = `confirm_member` in `write_session`, then set the session cookie and clear the pending cookie. Map `InvalidToken` to one "link invalid or expired" page, `Conflict` to "username taken / already registered".
- A second pending row for the same address is allowed (no supersede); the first to confirm wins, the other gets `Conflict(reason="email_taken")`.
- `purge-expired` (CLI) does not yet delete old `pending_registrations`; add it (not my file).
- Hashing runs inside the caller's write transaction (holds the write lock for one Argon2 hash, ~tens of ms in production).

## Known-broken
- None.

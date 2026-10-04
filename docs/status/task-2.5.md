# Task 2.5 - Login, forgot/reset, rate limits, pending-action change, gate removal, minimal routes

Status: done. Full suite (incl. e2e) 1299 passed, 0 failed, 0 errors.

## What changed
- `app/services/login.py` (new): `authenticate`, `sign_in`, `normalize_username`, `can_sign_in`. One generic `InvalidCredentials`; dummy Argon2 for unknown/unusable users; DB-backed limits `login` (5 / 15 min per username+IP) and `login_ip` (20 / 15 min per IP). Success rotates the session and consumes the pending coffee once through `onboarding.start_session_and_record`; audit `user.login`.
- `app/services/recovery.py` (new): `request_reset`, `peek_reset`, `reset_password`, `hash_token`. SHA-256 tokens, single use, TTL `settings.RESET_TTL_MINUTES`; limits 3/h per username, 10/h per IP, 6/h per recipient (hashed). Reset revokes all user sessions and linked admin sessions.
- `app/services/pending.py`: kinds `single`, `double`, `view_site`; `create_view_site_pending(db)`.
- `app/services/onboarding.py`: only `start_session_and_record` and constants remain (v1 register/select-profile removed).
- Gate removed: `gate.py`, `/join`, `/profiles*`, gate cookie, `ACCESS_CODE` setting/production handling, templates, strings, README/.env.example/compose/Dockerfile rows, tests.
- Routes (`app/web/routes_user.py`): `/login`, `POST /logout` (replaces `/account/leave`), `/register`, `/verify/{token}` (GET writes nothing, POST confirms), `/forgot`, `/reset/{token}`. Anonymous scan stores pending coffee and redirects to `/login` (plain "Create account" link).
- Pre-session CSRF: `coffee_csrf` cookie (`deps.form_csrf_token`, scope "anon"); session-bound token once signed in.
- `python -m app.cli purge-expired` also deletes expired/consumed `pending_registrations` and `password_reset_tokens` (audit meta keys `pending_registrations`, `reset_links`; the audit log forbids keys containing "token"/"password").
- `scripts/smoke.sh` now logs in with `SMOKE_USERNAME` / `SMOKE_PASSWORD`.

## Decisions
- The route catches `InvalidCredentials` inside `write_session()` so the failure rows commit. Argon2 runs inside the write transaction (as in registration). Failed logins are not audited (rate-limit rows only); successes are.
- Recovery never reveals whether a username exists; the recipient cap drops the mail silently.
- `OnboardResult.created` is kept only because tests/test_platform_registration.py reads it.

## Later tasks must know
- 3.1: `recovery._recovery_address(db, user)` is local (member -> own email, guest -> active member sponsor's email). Swap for `registration.recovery_address` and delete it. Guest branches of `/verify` are not implemented.
- 5.1: anonymous `/overview` should call `pending.create_view_site_pending` (set the pending cookie) and redirect to `/login`; `/login` already shows the "overview after sign-in" notice and `_signed_in` redirects view_site to `/overview`.
- 6.1: README still carries the original "Normal-user identity is based on a long-lived browser session and voluntary profile selection..." sentence because tests/test_ops_scripts.py requires it; it is followed by a v2 note. Reword text and test together. Privacy page wording mentions email and password hash; 3.1 may refine.
- Admin QR page still offers a free-text line (hint mentions "access code"); not owned here (admin strings).
- tests/test_e2e_scan.py was updated to the login flow and passes with Chromium.
- Renamed test: tests/test_audit_security_gate_sessions.py -> test_audit_security_login_sessions.py (rewritten for login limits, cookie hardening, sessions).
- New tests: tests/test_platform_login.py (54), tests/test_user_auth_web.py (62).

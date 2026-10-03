# core-b status

## Done
- services: signing, sessions, pending, onboarding, gate, ratelimit; web: tokens, deps, middleware, templating, health, main; strings*; templates/base.html, error.html; static/app.css
- tests: test_platform_services.py, test_platform_web.py (suite 194 green); uvicorn smoke: /healthz, /readyz 200 on migrated DB

## Next
- nothing (brief complete); pending requests for A in requests.md

## Entry points for web agents (U, M)
- Writes: `with app.db.write_session() as db:` inside the route (commit before the response). Reads: `Depends(deps.get_read_db)`.
- Render: `app.web.templating.render(request, "user/x.html", {...}, status_code=, headers=)`; context gets `settings`, `t`, `csrf_token`; filter `|money`. Templates extend `base.html` (blocks title, head_extra, body_class, header_extra, content, scripts_extra). Assets via `/static/...`.
- `app.web.deps`: `current_user(request) -> UserContext(session, user) | None`, `require_user` (dep, 303 /join), `forget_user`, `has_gate`, `has_gate_cookie`, `require_gate` (dep, 303 /join), `require_csrf` (dep; form field `csrf_token`, bound to user session else gate cookie), `verify_csrf_form(request, scope, key)` (admin: `("admin", admin_session.csrf_secret)`, token via `tokens.csrf_token("admin", secret)`), `client_ip(request)`, `Redirect(path)` exception -> 303, `CSRFError`, `parse_uuid`.
  Cookies: `set_session_cookie(resp, raw)`, `clear_session_cookie`, `set_gate_cookie(resp)`, `set_pending_cookie(resp, pid)`, `clear_pending_cookie`, `pending_id(request)`.
- `app.web.tokens`: `make_scan_token(kind)`, `verify_scan_token(token, kind) -> ScanToken(kind, nonce, issued_at) | None` (field `token`), `make_registration_token()`, `verify_registration_token(token) -> nonce | None` (field `registration_token`), `csrf_token(scope, key)`, `verify_csrf`.
- `app.web.middleware.no_store(resp)` (default for all non-static responses anyway). Middleware already rejects cross-site unsafe requests (Sec-Fetch-Site/Origin) with 403 and bodies > 64 KiB with 413.
- Services: `sessions.create_session/issue_session/resolve_session/revoke_session/revoke_user_sessions/active_session_count`; `pending.create_pending(db, kind, nonce)`, `get_pending`, `consume_pending`;
  `onboarding.register_and_start_session(db, *, display_name, chair_id, pending_id=None, registration_nonce=None, old_session_id=None)` and `select_profile_and_start_session(db, *, user_id, pending_id=None, old_session_id=None)` -> `OnboardResult(user, raw_token, session, event, coffee_status, created)`; coffee_status in `COFFEE_NONE|RECORDED|EXPIRED|NO_PRICE`. Route then sets session cookie, clears pending cookie, `forget_user(request)`.
  `gate.check_access_code`, `make_gate_cookie`, `verify_gate_cookie`; `ratelimit.check_rate(db, bucket, key, limit, window)` (counts every call) or `is_limited` + `record_hit` (failures only); limit tuples `ratelimit.ACCESS_CODE_FAILURES/REGISTRATION/PROFILE_SEARCH/ADMIN_LOGIN_FAILURES` = (bucket, limit, window_s). A failed attempt must be recorded in its own committed write_session before rendering the error.
- Unhandled `ServiceError`s map to safe pages (NotFound 404, Forbidden/UserInactive 403, RateLimited 429, Conflict 409, else 400); `OperationalError` -> 503 "please try again".
- Strings: add keys to your own module (`strings_user.py` "user.*", `strings_admin.py` "admin.*"); `{app_title}`, `{chair_label}`, `{currency}` are always available.

## Notes/Blockers
- Registration single use: user id = HMAC(SECRET_KEY, nonce) -> PK uniqueness; duplicate submit returns the same profile + coffee with a fresh session (`created=False`).
- `onboarding._new_user` mirrors `users.create_user` until A adds `user_id=` (requests.md). `merge_users` still uses direct UPDATE (requests.md).
- /join has no CSRF token (no binding yet); protected by the Origin/fetch-metadata check and the failure rate limit.
- FastAPI docs UI is always off; `/openapi.json` only in development.

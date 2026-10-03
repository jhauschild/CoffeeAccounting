# Brief 01b — core-platform (agent name: `core-b`)

Dir: `/home/claude/coffee-ledger` (branch `main`). You run alone, after core-a is merged. Read `docs/agents/00-protocol.md`, `docs/ARCHITECTURE.md`, and PROMPT §3, §5, §9, §10 (the parts relevant to you). Read `docs/status/core-a.md` and skim `app/services/ledger.py` signatures before coding.

## Build (everything marked **B** in the architecture)

1. `app/services/sessions.py`: 256-bit opaque token, store SHA-256 only; `issue_session`, `resolve_session` (invalid if revoked/expired/user inactive or merged; update `last_seen_at` at most once per hour), `revoke_session`, `revoke_user_sessions`. Replace core-a's temporary raw UPDATE in `merge_users` with a call to this (coordinate by editing nothing of A's: file a request in `docs/status/requests.md`, or leave it; orchestrator will handle).
2. `app/services/pending.py`, `onboarding.py`: `register_and_start_session` and `select_profile_and_start_session` run in the caller's single write transaction: create user (register only) → atomically consume the pending action (`UPDATE … WHERE consumed_at IS NULL AND expires_at > now`, proceed only if one row changed) → `record_coffee` with the stored nonce → issue a **new** session token (rotate; revoke the browser's old session if given). Registration double-submit protection via a one-time registration token (signed, single-use, tracked server-side or via unique constraint; your choice, document it).
3. `app/services/gate.py`: `ACCESS_CODE` constant-time check; signed `coffee_gate` cookie value (1 h). `app/services/ratelimit.py`: DB-backed `check_rate`.
4. `app/web/tokens.py`: signed scan token (kind, nonce, issued-at, 30 min expiry) and CSRF tokens (per user/admin session). `app/web/deps.py`: DB deps, current user session (from `coffee_session` cookie), CSRF verification, client IP honoring `TRUSTED_PROXY_IPS` only.
5. `app/web/middleware.py`: security headers (strict CSP `default-src 'self'`, HSTS in production, `X-Content-Type-Options`, `Referrer-Policy: same-origin`, `frame-ancestors 'none'`), request-size limit, `Cache-Control: no-store` helper.
6. `app/main.py` `create_app()`: settings, middleware, static mount, routers from `app.web.routes_user` and `app.web.routes_admin` (create empty stubs exposing `router = APIRouter()`), `app/web/health.py` (`/healthz`, `/readyz` = DB reachable and at Alembic head), safe error handlers (no stack traces in production; FastAPI docs/OpenAPI disabled in production), generic "please try again" page for transient DB errors.
7. `app/strings.py` (+ `strings_common.py`, empty `strings_user.py`, `strings_admin.py`), `templates/base.html`, `static/app.css` (mobile-first, large tap targets, light/dark via `prefers-color-scheme`, no external assets).
8. Tests `tests/test_platform_*.py`: session lifecycle, rotation, expiry, revocation, inactive/merged invalidation; pending-action atomic consumption incl. threaded double submit → exactly one coffee and one profile; onboarding with and without pending; gate and rate limiting; token signing/expiry/tamper; security headers and CSP; production config startup failures; `/healthz`, `/readyz`; error handlers hide details.

## Done when

Suite green, committed on `main`, `uvicorn app.main:app` starts against a migrated DB (smoke-check `/healthz` with curl), `docs/status/core-b.md` records the exact names of dependencies/helpers the web agents should use (this is their entry point; make it precise but short).

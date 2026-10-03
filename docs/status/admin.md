# admin status

## Done
- services: `admin_auth` (Argon2id, TOTP + 8 hashed recovery codes, pending->full session rotation, DB rate limit, bootstrap), `stats` (dashboard, user table, detail, audit page), `exports` (CSV with BOM/delimiter/decimal/injection guard, labeled SVG QR); `cli_admin` (create-admin, set-admin-chairs, reset-admin-password, reset-admin-totp, disable-admin [--enable], list-admins, bootstrap-admin, qr)
- web: `admin_deps` (single dependency set: require_admin / require_global_admin / admin_user_access / global_user_access / require_admin_csrf), `admin_login`, `admin_users`, `admin_manage`, `routes_admin` (router lifespan runs the bootstrap), templates/admin/*, static/admin.css + admin/{adjust,print}.js, strings_admin
- tests: test_admin_{auth,cli,stats_exports,web_login,routes_authz,actions,views,audit_coverage}.py (+ tests/admin_support.py); full suite green

## Next
- nothing (brief complete)

## Notes/Blockers
- Router enumeration test lists routes from the admin routers and cross-checks against `app.openapi()` (FastAPI 0.142 `app.routes` holds `_IncludedRouter` objects, not flat routes).
- Chair-admin dashboard/exports scope = events of users who currently are (effective user) in their chairs; per-chair grouping shows only their chairs by event chair.
- Merged profile detail redirects to the effective profile (404 if that is out of scope).
- Audit view and prices/chairs pages are global-only; QR page, exports, dashboard open to every admin (scoped).
- Services re-load the admin via `db.get` (routes pass detached admins from the read session).
- Verified with uvicorn smoke: bootstrap at start, /admin/login and static files 200. No browser test for the admin UI (no browser in this task).

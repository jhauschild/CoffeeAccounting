# fixer-2 status

## Done
- Admin login: `admin_auth.start_login` (no db arg now) hashes outside any write txn (reserve attempt -> hash -> short write txn); success releases the reserved failure. Per-IP cap `ADMIN_LOGIN_FAILURES_IP` (15/15 min); rate-limited audit written once per window per exhausted cap.
- Access code limiter: check + count in one write_session, correct code releases the hit. `ratelimit.ip_key` keys IPv6 by /64 (used in join, register, profiles, admin login).
- config: dev mode with published DEV_* secrets refuses https / non-local PUBLIC_BASE_URL; compose sets ENVIRONMENT=production (.env.example already did).
- db: `hide_parameters=True`. exports: quote-escaped SVG aria-label. requirements pinned.
- All 6 security xfails removed; 774 tests pass.

## Next
- none.

## Notes/Blockers
- pip-audit not installed in venv, so left as `>=2.7` in requirements-dev.txt.
- Audit rows keep the full client IP; only rate-limit keys use the /64.

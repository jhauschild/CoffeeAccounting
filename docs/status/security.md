# security (brief 06) status

## Done
- Read protocol, brief, ARCHITECTURE, PROMPT §3/§5/§6/§9; code review of middleware, deps, tokens,
  signing, gate, sessions, pending, onboarding, ratelimit, admin_auth/deps/login/users/manage, exports.
- Baseline: 444 tests pass.

## Next
- tests/test_audit_security_gate_sessions.py, _authz_csrf.py, _admin_auth.py, _injection_config.py
- pip-audit, secrets grep, final findings list.

## Notes/Blockers
- Candidate findings: access-code limiter TOCTOU (read check, separate write); admin login holds
  SQLite write lock during Argon2 (unauth DoS); no per-IP cap across usernames (audit flood);
  rate-limit keys use full IPv6 address; engine without hide_parameters (secrets in error logs).

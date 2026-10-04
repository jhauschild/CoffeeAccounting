# Task 1.2: v2 settings, passwords, key derivation

Status: done. Commit "config: v2 settings, passwords, key derivation (task 1.2)".
Full suite (e2e excluded): 538 passed, 57 failed, 238 errors. Baseline was 496 passed / 57 / 238 (the same v1 admin files from task-1.1.md); no new failures. 42 passes more than baseline: 35 new tests, plus existing config tests (access-code cases removed, new MAIL_FROM cases added).

## What changed
- `app/config.py`: new settings `mail_backend` (None resolves to `smtp` in production, `console` otherwise; the field is never None after validation), `smtp_host/port/security`, `mail_from`, `mail_file_dir`, `secrets_dir`, `mail_max_per_hour`, `allowed_email_domains` (comma string; `allowed_email_domain_list` property, lower-cased), `verification_ttl_hours`, `guest_approval_ttl_days`, `reset_ttl_minutes`, `password_min_length`, `stepup_window_seconds`, `balance_totp_required` (None resolves to true in production, false otherwise), `argon2_time_cost/memory_cost_kib/parallelism` (defaults = argon2-cffi 3/65536/4). Production refuses: backend != smtp, empty SMTP_HOST, port outside 1..65535, ssl+587 or starttls+465, MAIL_FROM empty or without "@", PASSWORD_MIN_LENGTH < 8. Messages name the variable only, never the value.
- `ACCESS_CODE` is optional in production. Decision: an unset/short/placeholder code in production is replaced at startup by a random token, so the v1 gate (still present until task 2.5) cannot be opened with the published dev value. The "DEV_ACCESS_CODE on a public URL" check in development was dropped (only the DEV_SECRET_KEY check remains). `ADMIN_TOTP_REQUIRED` untouched.
- `app/services/passwords.py`: `hash_password(pw)` (no policy, only max 128), `verify_password(hash, password)` (same argument order as `admin_auth`), `needs_rehash(hash)`, `verify_and_rehash(hash, password) -> (ok, new_hash|None)`, `verify_dummy(password)` (timing for unknown users), `validate_policy(password, username, email=None)`, `get_hasher()`. Errors: new `InvalidPassword(InvalidInput)` in `errors.py`, code `invalid_password`, `context["reason"]` in `too_short | too_long | equals_username | equals_email_local`.
- `app/services/keys.py`: `derive_key(label, length=32)` (HKDF-SHA256, salt None, info = label utf-8, from SECRET_KEY), `fernet_key(label)`. `cryptography==50.0.2` added to requirements.txt and installed in the venv.
- `tests/conftest.py`: cheap Argon2 (1 / 8 KiB / 1) via TEST_ENV only. `.env.example`: commented mail/accounts section appended. `README.md`: env table rows added (required by `test_ops_scripts` which checks every setting is documented in README and `.env.example`).
- Existing tests adjusted: `test_core_money_time_config.py` and `test_platform_web.py` (production env needs MAIL_FROM; ACCESS_CODE refusal cases removed, MAIL_FROM/MAIL_BACKEND cases added).
- New: `tests/test_core_config_v2.py`, `test_core_passwords.py` (includes the production-defaults test), `test_core_keys.py`.

## Later tasks must know
- Not changed: `admin_auth` still has its own module-level `PasswordHasher()` (production-default params, so tests there run with full-cost Argon2) and its own 12-char admin password minimum. Switching it to `passwords.get_hasher()` is trivial and speeds up admin tests; left for task 4.1.
- Not migrated: v1 token/CSRF signing (`app/services/signing.py`, `app/web`) keeps its own derivation; use `keys.derive_key` with distinct labels (e.g. `mail-login` via `fernet_key`) for new code.
- `docker-compose.yml` does not yet pass `MAIL_FROM`/`SECRETS_DIR`; production now refuses to start without MAIL_FROM (ops task needs to add it and a `/secrets` volume).
- Task 1.2's worktree started on `62a6993` (not the v2 tip); I reset it to `a5cc4ef` before working.

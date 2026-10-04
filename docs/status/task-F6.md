# Task F6: final-audit fixes (M1, L1, L2, L3)

Source: `docs/status/review-final.md` section 3. Tests: `tests/test_final_f6.py` (30 tests). Full suite incl. e2e:
`1952 passed, 4 skipped, 0 failed` (baseline 1922 passed, 4 skipped).

## M1 Argon2 no longer runs under the SQLite write lock
- `login.start_sign_in` (new, used by `POST /login`): short write txn (limits, read stored hash, count the attempt as a
  failure up front like `admin_auth.start_login`, so parallel guesses stay strictly budgeted), Argon2 verify / rehash /
  dummy hash with NO transaction open, short write txn that re-loads the account and fails like a wrong password when it
  can no longer sign in or its hash changed, else releases the counted failure, upgrades the hash, records the success,
  rotates the session, consumes the pending action, audits. Generic failure, dummy hash for unknown users, 5/20 failure
  limits and `RateLimited`-before-any-check are unchanged. `login.sign_in` / `authenticate` stay as the
  single-transaction forms (tests, `long_scenario.py`), now also under the success cap.
- New per-address cap on SUCCESSFUL sign-ins: `ratelimit.LOGIN_SUCCESS_IP = ("login_ok_ip", 60, 10 * 60)` (IPv6 by /64),
  checked before any password check (a limited address gets 429 even with the right password), recorded on success.
  Documented in the `login.py` docstring and README. A shared NAT address with more than 60 real sign-ins in 10 minutes
  would be limited; that is the intended trade-off.
- Registration: the route hashes BEFORE `write_session` (`_prehash` in `routes_user.py`: skipped when the address is
  already over its limit or the length is out of range, so refused requests cost no Argon2) and passes
  `password_hash=` to `registration.begin_member` / `begin_guest` (new optional parameter; policy is still checked, the
  hash is computed inside only when none is given). `confirm_member` / `approve_guest` never hashed (they copy the
  pending row's hash).
- Reset: `recovery.check_reset(db_read, token, pw)` (read-only: token, account, policy) -> hash -> `reset_password(...,
  new_hash=)` in a short write txn that re-checks token (atomic consume), account state and policy.
- Password change: `account.start_change_password` (same three-phase shape as sign-in; wrong guess counted up front,
  released on success and on a policy refusal; changed hash or inactive account while hashing fails safely).
  `change_password(db, ...)` is kept for tests.
- Structural regression tests: a slow hasher is patched in, and while the action runs another connection repeatedly takes
  `BEGIN IMMEDIATE`; the longest wait must stay under 0.3 s (hash sleeps 0.6 s). A control test proves the probe sees a
  lock held by the single-transaction form. Covers sign-in (right, wrong, unknown user, over HTTP), registration, guest
  request, reset, password change.
- NOT changed (outside the named items): `admin_auth.change_password` (admin area, signed-in admin) still hashes inside its
  transaction.

Measured with `docs/status/repro/prod_instance.py` section "dos" (production Argon2 cost, uvicorn flags of run.sh):

| scan latency | before (v2) | after |
|---|---|---|
| alone | median 0.011 s, max 0.014 s | median 0.015 s, max 0.025 s |
| 1 sign-in loop | median 0.574 s, max 3.708 s | median 0.027 s, max 0.035 s |
| 3 sign-in loops | median 1.772 s, max 4.297 s | median 0.059 s, max 0.111 s |
| 6 sign-in loops | median 0.206 s, max 0.678 s (one sign-in 503) | median 0.141 s, max 0.208 s |

Whole script: before 260 checks / 1 FAILED (the dos check), after 260 checks / 0 FAILED, exit 0. The remaining latency
with 6 loops is CPU contention of the hashes themselves (no lock). The 6-loop "before" row happened to be milder than the
audit's runs (3.8 s); the 1- and 3-loop rows reproduce the finding.

## L1 negative adjustments
`ledger.admin_reverse_event` raises the new `errors.NotReversible(Conflict)` (code `not_reversible`) for `quantity <= 0`;
flash string `admin.err.not_reversible` ("A negative adjustment cannot be reversed. Book the opposite adjustment
instead."); `stats.ConsumptionRow.can_reverse` is false for them so the admin user page has no Reverse button.
`repro_reverse_negative_adjustment.py` now exits 0. Tests: service, positive adjustment and coffee still reversible, page
without button, hand-made POST gives 303 `?err=not_reversible` with the text on the page (no 500), also through the step-up
`submit` helper.

## L2 empty TRUSTED_PROXY_IPS
- `create_app()` logs one WARNING at start in production when the list is empty; `deps.client_ip` logs a WARNING (module
  clock, once per hour, production only) when a request carries `X-Forwarded-For` from a peer that is not trusted. The
  message names the peer only, never the header value. Forwarded headers are still not trusted by default.
- `.env.example`, README (step 4 + config table), `docker-compose.yml` (commented `TRUSTED_PROXY_IPS=172.18.0.0/16` and a
  commented pinned network `172.28.0.0/16`), `scripts/smoke.sh` header note (the smoke script cannot see the problem).
- `repro_shared_ip_lockout.py` still exits 1 on purpose: with the empty default the behaviour is unchanged (the fix is the
  warning and the documentation, not trusting headers).

## L3 lock file
- `requirements.lock`: `uv pip compile requirements.txt --universal --generate-hashes --python-version 3.13 -o
  requirements.lock` (uv 0.11.32; command is the header of the file). 36 packages (13 direct + transitive incl. the
  `uvicorn[standard]` extras), every artifact hashed, universal (Linux x86-64 / arm64). Checked: a fresh venv installs it
  with `pip install --require-hashes`, `pip check` clean, `import app.main` works, and the versions equal the ones in the
  reference test venv (which holds extra dev packages only).
- `Dockerfile`: `FROM python:3.13-slim` (digest note in a comment and README: no registry access here, a digest could not
  be looked up), `COPY requirements.lock`, `pip install --require-hashes --no-deps -r requirements.lock`.
  `requirements.txt` / `requirements-dev.txt` stay for development. README "Reproducible build" explains regeneration.
- `pip-audit -r requirements.lock`: `No known vulnerabilities found` (exit 0).
- Tests: every `requirements.txt` package is in the lock at the same version with a hash; every lock entry is pinned with
  hashes; transitive packages present; Dockerfile uses the lock with `--require-hashes` on 3.13.
- No image was built (no Docker daemon): not verified that the lock installs on the real `python:3.13-slim` image, only on
  the local 3.13 venv.

## Later tasks must know
- The web layer must call `login.start_sign_in`, `account.start_change_password`, `recovery.check_reset` + `reset_password(new_hash=)`
  and the registration `password_hash=` path; never hash inside `write_session()`.
- Known-broken tests: none.

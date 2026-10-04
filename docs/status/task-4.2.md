# Task 4.2: step-up dependency and confirm pages

Status: done. Commit "admin: step-up confirm flow for balance changes (task 4.2)".

## What changed
- New `app/services/stepup.py` (flow, registry, signed payload, nonce, audit), `app/web/admin_stepup.py` (the one executing route `POST /admin/stepup/confirm`), `templates/admin/confirm.html`, `templates/admin/stepup_invalid.html`, strings `admin.stepup.*`, `admin.msg.already_executed`.
- `admin_deps.py`: `require_stepup` (async dependency), `StepupRoute` (route class that turns a `StepupResponse` raised by the dependency into the page), `confirm_page`, `preview`, `needs_code`.
- `admin_auth.open_stepup(db, session_id=, admin=, code=, ip=)` returns `window|totp|recovery_code|invalid|limited|no_session`; wrong codes use the existing admin limiter (bucket `admin_login`, step `stepup`) and audit `admin.stepup.failed`; success audits `admin.stepup.opened` (method, never the code). Replay (120 s) via `_totp_matches`; recovery codes via `_consume_recovery_code` on the admin re-read INSIDE the write transaction (concurrency safe, tested with threads at service and HTTP level).
- Entry routes `POST /admin/users/{id}/payment|adjustment|events/{eid}/reverse|merge` keep their URLs but only PREVIEW: `stepup.prepare` runs the real action inside a write transaction that is always rolled back (nothing persisted, no audit, no nonce), so errors are identical to execution (invalid amount, out of scope, already reversed, ...) and the resulting balance is real. The page shows action, person + chair, amount, balance now / afterwards, note, merge target, signed `payload`, `nonce`, and a `code` field only when the window is closed and `BALANCE_TOTP_REQUIRED`.
- `POST /admin/stepup/confirm` (CSRF + `require_stepup`): payload must verify (HMAC, key `derive_key("stepup-payload")`, 10 min, fields `v,k,p,n,a,s,iat`, bound to admin id AND admin session id, separate `nonce` form field must equal the signed one), nonce unspent, then window open / fresh code / `BALANCE_TOTP_REQUIRED=false`. `stepup.run` inserts `used_nonces` in the same transaction as the action; unique violation => `AlreadyExecuted` => redirect with `msg=already_executed`, nothing booked twice. A failing action (ServiceError) rolls back the nonce too, so the confirm form can be retried. Payments get `idempotency_key = "stepup:<nonce>"`. Audit: the ledger's own entry plus `stepup.executed` {kind, authorised_by = window|totp|recovery_code|not_required, amount_cents, ids}; rejected payloads audit `stepup.rejected` {reason}.
- Window is fixed: opened only when closed, never extended; a code supplied while the window is open is not consumed.
- `routes_admin.py` (not in the ownership list, one-line change) includes the new `admin_stepup` router.

## For task 4.4 (set balance, remittances, /admin/groups)
1. In `stepup.py` write `parse` (raw form dict -> canonical JSON-safe params, may raise ServiceError), `execute(db, admin, params, *, nonce, ip, now) -> ActionResult` (call `ledger.set_balance(... idempotency_key=idempotency_key_for(nonce))` / `groups.record_remittance(...)`), `balance_user_id`, `back_path`; `register(Action(kind, "admin.stepup.action.<kind>", ...))`; add the label string. For a remittance, `ActionResult.user_id` is the person shown (the group admin's account); `balance_user_id` is whose balance to display.
2. Add a preview route that depends on `require_admin_csrf` + role dependency and returns `ad.preview(request, ctx, "<kind>", raw_dict, error_path=...)`. No dependency on require_stepup there; the confirm route is shared.
3. Add the preview path to `PREVIEW_POSTS` in `tests/test_admin_routes_authz.py` (the enumeration test fails until you do) and to `POST_DATA`; extend `BALANCE_PATH` in `tests/admin_support.py` if the test helper `submit()` should run both steps for it. `test_balance_services_are_only_called_from_the_step_up_registry` fails if a route module calls `add_payment/add_adjustment/admin_reverse_event/merge_users/set_balance/record_remittance` directly. Role assignment (task 4.3) POSTs go to `NON_BALANCE_POSTS`.
4. The confirm template shows `view.extra.into` only for merge; add more rows by extending `ConfirmView.extra` and the template.

## Tests
- `tests/test_admin_stepup.py` (40 tests): read-only preview, per-field tamper, expiry/bindings, wrong code/rate limit, window fixed/expiry, TOTP replay, recovery single use + concurrency (service and HTTP), double submit / concurrent double submit, failed action keeps nonce, scope and own-balance rule, dev flag, audit contents.
- `tests/test_admin_routes_authz.py`: new allow-list enumeration (`NON_BALANCE_POSTS`, `PREVIEW_POSTS`, `STEPUP_POSTS`) and the static call scan; `tests/admin_support.py`: `submit()`, `confirm()`, `confirm_fields()`; test_admin_actions / audit_coverage / ledger_prices / ledger_reversal now use the two-step helper.
- Full suite (e2e excluded): 1405 passed, 0 failed, 0 errors. `tests/test_e2e_scan.py`: 1 passed. Baseline was 1354 passed (e2e included).

## Notes
- Preview takes the SQLite write lock briefly (always rolled back); acceptable at this load.
- Bound to the admin session: a payload prepared in one browser session cannot be confirmed in another (re-login within 10 minutes means start again).
- Known-broken: none.

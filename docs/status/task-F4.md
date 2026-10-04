# Task F4: fixes for the M4 review (docs/status/review-M4.md)

All fixes have regression tests in `tests/test_final_f4.py` (42 of its 49 tests fail on the v2 tree; the rest are
the "test gap" tests that were simply missing).

## What changed
- M1 `ledger.add_payment`: a correction takes `chair_id` from the corrected payment. Checker rule `correction_chair`.
- M2 `ledger.add_payment`: a correction may be recorded only by the original's collector or a head admin
  (`Forbidden`), needs the opposite sign and `abs(amount) <= abs(original)` (`InvalidAmount`; partial corrections
  stay possible, one correction per payment). Checker rules `correction_sign`, `correction_amount`,
  `correction_recorder` (recorder = collector or a head admin).
- M3 `users.update_profile`: any chair change of a user linked to an ACTIVE `admin_users` row with role `chair`
  raises `Forbidden` (user or admin actor; a head admin must remove the role first). `POST /account/edit`
  catches it and shows a 403 form error (`user.edit.chair_locked`).
- M4 `registration._check_username_probe` (used by `begin_member` and `begin_guest`): per-IP bucket
  `ratelimit.USERNAME_PROBE` = 10 per 15 minutes. A "taken" answer (user or CLI admin) records one hit and
  re-raises the `Conflict`; the caller MUST catch it inside its `write_session()` block so the hit commits
  (`routes_user.register_submit` does; the future guest route in 3.1 must do the same, see the docstring of
  `_check_username_probe`). Over the cap -> `RateLimited` (429) before the name is looked at, so the cap is no oracle.
  The registration / guest-request IP caps are now recorded only after the username check, so probes do not
  eat them. Other validation errors still roll back and burn nothing.
- M5 `app/web/accesslog.py` (`AccessLogMiddleware`, logger `app.access`, one line `METHOD path -> status`,
  never the query string, `/verify/<redacted>` and `/reset/<redacted>`); `scripts/run.sh` uses `--no-access-log`;
  the 500 handler in `app/main.py` redacts the path too. `deploy/Caddyfile` (log filter on URI and Referer) and
  `deploy/nginx.conf` (maps + `log_format coffee`, `error_log ... crit`) redact the prefixes; `deploy/README.md`
  explains why. README.md untouched (task 6.1 should link to `deploy/README.md`).
- L3 `mail._ADDRESS_RE` local part is `[A-Za-z0-9._+-]{1,64}` (also used by `registration.validate_email`).
- L4 `config._valid_sender` (production): MAIL_FROM must parse to a normalised address whose domain has a dot and
  is not localhost. `mail.sender_address()` raises `MailError("not_configured")` instead of falling back in
  production (development keeps `noreply@localhost`).
- L5 `mail_templates.neutralise_urls` removes URL-looking text (`scheme://...`, `//host...`, `www....`); applied in
  `registration.clean_display_name` (member and guest registration) and again in the mail template. The sponsor
  mail shows the name on its own quoted line (`mail.sponsor.body`).
- L6 `signing._key` = `keys.derive_key("signing:<purpose>:<extra>")` (HKDF, one label per purpose); this also
  covers CSRF (`csrf`), `registration._email_key` (`register-email`) and the admin recovery-code / TOTP-reuse MACs
  (`admin-recovery`, `admin-totp-used`). Existing cookies, CSRF tokens, scan tokens and stored admin recovery-code
  MACs become invalid (nothing deployed): after upgrading, admins need new recovery codes.
- L8 removed: `strings_admin.py` `admin.qr.line_hint` wording (one line; that file belongs to the 4.4 agent, merge
  trivially), `.profile-name` in `static/user.css`, "access code" in the `audit.py` docstring. Left alone:
  `app/web/admin_manage.py:132` docstring "(e.g. an access code)" (admin_* file owned by 4.4) and README.md (6.1).

## Tests changed
- `tests/test_core_authz_v2.py::test_scope_follows_a_chair_change_of_the_linked_user`: update_profile now refuses; the
  test asserts that and then moves the user by SQL to keep the scope check.
- `tests/test_platform_mail_templates.py::test_guest_names_are_single_line_and_not_in_subject`: the URL in the name is
  now removed.
- `tests/test_platform_registration.py`: added `test_username_taken_answers_do_consume_the_probe_limit` next to the
  test that keeps pinning that other validation errors burn no limit.

## KNOWN-BROKEN (files owned by the concurrent 4.4 agent, not touched here)
Two v1 tests relied on arbitrary corrections and fail on this branch by design (M2):
- `tests/test_admin_actions.py::test_payment_correction_and_chair_admin_scope`: the group admin `cc` corrects a payment
  collected by the head admin `gc`. Verified fix: lines 81 and 84 `post(cc, ...)` -> `post(gc, ...)` and the second amount `"1"` -> `"-1"`.
- `tests/test_admin_audit_coverage.py::test_every_admin_action_is_audited_without_secrets` (line ~80): the correction
  `amount="1"` has the same sign as the 3,00 payment. Fix: `amount="-1"`.

## Later tasks
- 3.1 (guest approval route and guest register form): catch the username `Conflict` inside the `write_session()` block.
- 4.4 UI: a correction form should offer only the original's collector / head admins and a negative-of-original default.

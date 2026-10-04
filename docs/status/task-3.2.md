# Task 3.2: scan result page and account page

Status: done. Full suite incl. e2e: 1569 passed, 0 failed, 0 errors (baseline 1535).

## What changed
- `/coffee/done/{event}` and `/account` show the balance in words via `user_views.headline` (uses
  `overview.balance_label`, money through `format_money` inside `t()` keys): "Outstanding: €X", "Credit: €X" or
  "All settled". CSS classes `headline headline-owes|credit|even` (static/user.css). No minus sign. The old
  "Balance (to pay)" row is gone; `user.totals.balance` and `user.totals.credit` keys removed.
- "Shots this month: N" from `ledger.get_month_shots`; `user_views.month_shots` floors at 0 for display (a reversal
  booked this month for last month's coffee would otherwise show a negative number). The service value is unchanged.
- Links to `/account` and `/overview` (not built yet, task 5.1) on both pages. Undo block and window unchanged.
- Account page: display name, chair (read-only), username and e-mail (owner only), price, totals, history, payment
  history with direction in words (Payment / Paid back to you / Balance correction (credited|charged), "(correction)"
  tag; amounts shown without a sign), change-password form, privacy line, "Remove this browser" (POST /logout,
  revokes the current session only; same route as before, only the label changed).
- `POST /account/password` (CSRF): `current_password`, `password`, `password2`. New service
  `app/services/account.py::change_password`: current password required, `passwords.validate_policy`, revokes the
  user's OTHER sessions and ALL `admin_sessions` of any `admin_users` row linked to the user, audit `password.changed`
  (counts only). Wrong current password: `InvalidCredentials` + a hit in bucket `pw_change` (5 per 15 min per user;
  over the cap `RateLimited` -> 429 even for the right password). The route catches `InvalidCredentials` inside its
  `write_session()` block so the hit commits.
- `/account/edit`: for a user linked to an ACTIVE group-admin row the chair is shown read-only (no select). A submitted
  different chair is refused with 403 and `user.edit.chair_locked`, nothing is applied (name included). A missing
  chair field is accepted for them. The service guard from F4 stays as second line.

## Tests
- New `tests/test_user_pages.py` (28). Updated `tests/test_user_account.py` (headline wording, string-key list) and
  `tests/test_audit_security_authz_csrf.py` (`/account/password` added to the user POST inventory).

## Later tasks must know
- 5.1 builds `/overview`; both pages already link to it.
- `account.change_password` is the place for any other self-service credential change; the 6.1 privacy text may
  repeat the new "visible to every signed-in account" line (`user.account.visibility`).
- Running pytest with `-p no:logging` breaks the caplog tests (not a real failure).

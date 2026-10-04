# Review M4 (tasks 1.3, 1.4, 2.1-2.5, schema and models)

Reviewer: fresh context, tree at tag `v2` (4e1592b). Read-only: no application code or tests changed. Method: read the contract, PLAN-v2 (rev 4 wins), every task hand-off and all in-scope code; ran the 433 in-scope tests (green) and wrote throwaway attack scripts (outside the repo) against the services and the HTTP app. Observed results are marked "observed"; the rest is from reading the code.

Counts: critical 0, high 0, medium 5, low 8.

## Medium

### M1. A payment correction takes the user's current chair, so the chair roll-up splits and is wrong (money)
- `app/services/ledger.py:449` (`PaymentEvent(... chair_id=user.chair_id ...)`); contrast `ledger.py:221` (reversals copy the original's chair) and `app/services/groups.py:227` (remittance corrections copy the original's chair).
- Scenario (observed): group admin G books cash +500 for member U (chair A). U changes chair to B. Head admin corrects the payment with -500. The correction copies the collector G (G's held = 0, right) but is stored with chair B. `chair_rollup`: A collected 500 / held 500, B collected -500 / held -500 flagged negative. A permanently shows 500 "still held", B shows a bogus negative; `check-ledger` passes and only emits a note. Violates D3 ("chair stored on the event at event time") for the correction pair.
- Fix: in `add_payment` set `chair_id = original.chair_id` when `correction_of_id` is given; add a checker rule that a correction has the chair of the payment it corrects.

### M2. Any group admin of a chair can rewrite another group admin's held balance with an unbounded correction
- `app/services/ledger.py:436-447` (collector copied from the original; correction amount is only checked for non-zero and the global cap).
- Scenario (observed): A and B are group admins of chair X. A books +500 from member U. B calls `add_payment(user=U, amount=90000, correction_of_id=A's payment)`. Result: `groups.held(A) = 90500`, `held(B) = 0`, `check_ledger` ok. Equally, B can book -499 and cancel A's held money. Nothing relates the correction to the amount it corrects, and a second group admin may act on A's cash.
- Fix: require that a correction is recorded by the collector or a head admin, and that its amount equals minus the original (or at least that the user's resulting paid total stays unchanged); flag deviations in the checker.

### M3. A group admin can move their own chair and thereby take over another chair's scope
- `app/services/users.py:206-210` (`update_profile` with `actor_type="user"` has no group-admin guard); `app/web/routes_user.py:397` (`POST /account/edit` is live); scope derives from the linked user's chair at `app/services/authz.py:41-43`.
- Scenario (observed): group admin G (chair A) changes own chair to B via the account service; `add_payment` for a member of chair B then succeeds (it is Forbidden before). Plan A5 and PLAN section 7 ("chair change blocked for group admins") require this to be refused; there is no test. It also corrupts the roll-up: G's earlier collections stay under A while later remittances are stored with the chair at remittance time (B).
- Latent today (no UI creates group admins until 4.3) but the guard belongs in `update_profile`, not the route.
- Fix: in `update_profile` (user actor) raise `Forbidden` when a linked `AdminUser(role='chair', active)` exists for the user and the chair changes; add the test.

### M4. Free, unlimited username probing at /register, including CLI admin usernames
- `app/services/registration.py:196-197` (rate limit counted, then `validate_username(..., db)` raises `Conflict`); the route lets the exception roll back the transaction, which removes the rate-limit hit (`routes_user.py:240-262`); pinned by `tests/test_platform_registration.py:320` (`test_invalid_submissions_do_not_consume_limits`).
- Scenario (observed): 40 consecutive POSTs for an existing username all return 400 "username taken", never 429. A CLI admin username (`rootadmin`) is reported "taken" the same way. Usernames are the sign-in identifier and appear nowhere on the site, so this gives an unthrottled oracle for valid user names and for admin names (which then become targets for the admin-login guessing). The login limits (5 per username+IP, 20 per IP) are meaningless against an attacker who already knows the names.
- Fix: record the rate-limit hit in a step that survives the rollback (as login does for failures), or add a per-IP failure limit for the username check. Only the username/CLI-admin "taken" answer needs it; other validation errors leak nothing.

### M5. One-time tokens end up in the access log (24 h member link, 7 day guest approval link, 1 h reset link)
- `scripts/run.sh:11-14` (uvicorn started with its default access log), routes `/verify/{token}` and `/reset/{token}` (`routes_user.py:266, 277, 322-334`); the reverse proxies log the URI as well (`deploy/`).
- Observed: `INFO: 127.0.0.1 - "GET /reset/SECRETRESETTOKEN123 HTTP/1.1" 400`. Anyone who can read container or proxy logs can reset a password or approve a guest while the token is still valid, which defeats the hash-only storage of tokens.
- Fix: run uvicorn with `--no-access-log` (log the request line without the path for these two routes if access logging is wanted) and note the proxy log redaction in the README/deploy files (task 6.1).

## Low

### L1. Guest approval has no HTTP route; the mailed link is a dead end (acknowledged in task-2.5.md, assigned to 3.1)
- `app/web/routes_user.py:266-300`. Observed: `GET /verify/<guest token>` shows the member page "Confirm to create this account and sign in"; `POST` returns 400 "link invalid". The token is not consumed. Not a defect in the services (approve/reject are tested), but package 2 is not usable end to end for guests until 3.1.

### L2. Registration and forgot pages do not say "temporarily unavailable" when no mail login is stored (assigned to 3.x)
- PLAN section 1 (last bullet of "Mail login"): `routes_user.py:240-262, 303-317` never consult `mail_credentials.status()`. With no credentials the visitor gets the "mail sent" page, a pending row is stored and nothing is delivered (observed from the code path; background send fails with category `not_configured`).

### L3. Recipient addresses may contain `%`, `!`, `|`, `/` and other relay-hack characters
- `app/services/mail.py:65` (`_ADDRESS_RE`). Observed: `victim%evil.example@tum.de` passes `registration.validate_email` (domain is judged on the part after the last `@`). A relay that honours the percent hack would forward the verification mail to `evil.example`, bypassing the TUM-domain rule. Header injection itself is not possible (CR/LF/space/quotes rejected; observed).
- Fix: restrict the local part to `[A-Za-z0-9._+-]`.

### L4. Production silently falls back to `noreply@localhost` as sender
- `app/services/mail.py:136-142` vs `app/config.py:249-250` (production only checks that MAIL_FROM contains `@`). Observed: `MAIL_FROM="@"` starts, and `sender_address()` returns `noreply@localhost`. Fix: validate MAIL_FROM with `normalize_address(parseaddr(...)[1])` in `_validate_v2`.

### L5. A guest's display name is free text inside the mail to the sponsor (link spoofing)
- `app/services/mail_templates.py:61-63`. Observed: display name "Open https://evil.example/login now" renders as the first sentence of the sponsor mail, in front of the real approval link. Fix: put the name in quotes on its own line and strip URLs (or `://`) from display names.

### L6. HKDF with distinct labels not applied to token HMAC, CSRF and the register-email key (contract line 9)
- `app/services/signing.py:34-41` still derives keys with plain HMAC; `registration.py:181` (`_email_key`) uses it. The keys are purpose-separated and sound, so this is a deviation from the contract, not a break; `keys.py` already says "not migrated yet". Track it so the contract box is not ticked by mistake.

### L7. Anonymous mail-cap exhaustion is silent
- `app/services/mail.py:479-490` with `MAIL_MAX_PER_HOUR=30` global. One IP can trigger 10 registration mails plus up to 10 reset mails per hour (limits at `ratelimit.py:35-39`); two IPs exhaust the cap and every later verification or reset mail is dropped while the page says "sent". Accepted risk in the plan; worth a dashboard banner (plan already has "cap reached") and a note in the README.

### L8. Removal of the access gate is not completely clean
- `README.md:51` still says "voluntary profile selection" (pinned by `tests/test_ops_scripts.py`, noted in task-2.5.md); `app/strings_admin.py:198` ("For example the access code"); `static/user.css:15` (`.profile-name`, unused); `app/services/audit.py:40` docstring mentions the access code. No code path, setting, template, compose or `.env.example` reference remains (grep over app/, templates/, static/, scripts/, compose, Dockerfile, `.env.example`, deploy/).

## Test gaps against PLAN section 7 (packages 1 and 2)
- Recovery: "two guests of one sponsor each reset only their own account" has no test (only a single guest is exercised, `tests/test_platform_login.py:316, 528`).
- Roles: "chair change blocked for group admins" (see M3), and "group admin cannot change own chair" have no test.
- Group balance: no test for a correction after a chair change (M1) or for a correction recorded by a different group admin of the same chair (M2). `tests/test_core_groups.py:221` covers remittance corrections only.
- Guest HTTP flow (approve/reject over the web) and the "temporarily unavailable" page have no tests because the routes are missing (L1, L2).
- The guest-registration test `test_same_outcome_for_member_non_member_and_unknown_domain_address` (`tests/test_platform_guest.py:136`) does not match the PLAN list (a non-TUM address gives a validation error, not the neutral page); the implementation choice is reasonable because the allowed domains are public, but PLAN section 7 should be updated.
- `tests/test_platform_registration.py:320` pins the M4 behaviour as intended.

## Checked and fine
- Ledger: cash payment sets the collector to the recording admin; corrections copy kind and collector whoever records them; bookkeeping has no collector, needs a head admin and is never in `collected`; `set_balance` sign (`current - target`, observed 150 -> -200 books +350), idempotent replay, zero difference refused; month shots use local half-open bounds; own-balance rule holds on effective ids (a profile merged into the group admin's own account is blocked, observed); cross-chair and inactive-admin payments are Forbidden (observed).
- Schema: `alembic upgrade head`, `downgrade base`, `upgrade head`, `alembic check` clean; append-only triggers include `group_remittances`; CHECKs and partial unique indexes match the contract.
- Registration: tokens `token_urlsafe(32)`, only SHA-256 stored; GET /verify and GET /reset write nothing (observed: no row-count change in any table); expired/consumed/unknown tokens give one error; known and unknown email give byte-identical page and headers (observed, only the mailed text differs); guest request outcome independent of sponsor state; guests cannot sponsor (`_active_member`); CLI-admin usernames refused both ways (`username_taken`, `admin_auth.create_admin`).
- Login: one generic 401 body and headers for wrong password and unknown user (observed); dummy Argon2 with the same parameters; limits are checked before any hash and keyed per username+IP and per IP; session rotated and the old one revoked (observed); one pending coffee is consumed once across two logins with the same cookie (observed: second login got the "expired" notice, one event); no open redirect (fixed targets, whitelisted notice, `next` ignored; observed).
- Recovery: same page for known, unknown and guest usernames; the 3-per-username limit applies equally to unknown names (observed); the token is single use, a weak password does not burn it, a reset revokes all user sessions and linked admin sessions (observed: old session redirected to login, old password refused).
- CSRF: every state-changing user form (login, register, forgot, reset, verify, logout, edit, undo) returns 403 without a valid token, with a forged token and with a cross-site Origin (observed); cookies are HttpOnly, SameSite=Lax, Secure in production.
- Mail: plaintext only, headers re-sanitised in `to_email_message` (CR/LF/U+2028 in subject, display name and hand-built headers neutralised; observed); caps checked before the backend with hashed recipient keys and no address in `rate_limit_events`; verification cannot be disabled (`_client_ssl_context` refuses a non-verifying context, no plaintext fallback); AUTH only on an `SSLSocket`; failures raised as category only, `from None`; credential store encrypted with an HKDF key, 0700/0600 set with `fchmod`/`chmod`, temp file plus `os.replace`, wrong SECRET_KEY gives the fixed "re-run setup-mail" text; credentials absent from logs, repr/str, status and audit.

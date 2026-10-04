# Plan v2 (revision 3): username accounts, guest sponsors, open website, group admins, group balances, LRZ mail

Status: proposal, nothing implemented. Date: 2026-10-03.
Builds on `ARCHITECTURE.md` (module ownership A/B/U/M/O, service interfaces) and the original prompt. v1 is finished (776 tests); there are no existing user profiles, so no data migration is needed.

## Changes in revision 3

- **No guest search.** A guest types the email address of a group member; the request is mailed there.
- **Mail server:** `postout.lrz.de`, port 587 (STARTTLS) or 465 (implicit TLS), certificate verification always on.
- **Mail login is entered at deployment**, through an interactive setup step (never an environment variable, never in the database), stored encrypted in a separate volume, and kept out of backups, logs and the GUI.
- **Email testing strategy** added (section 7b): an in-memory mailbox for logic tests and a local fake SMTP server for protocol tests. A first spike already ran in this sandbox (11 of 11 checks passed).

## Changes in revision 2

- Sign-in is now **username + password** (not email). The TUM email only proves institute membership and is the recovery address.
- **Guests** register themselves, name a group member as sponsor by email, and the sponsor's email receives the verification link. This replaces the earlier "admin creates visitor accounts" decision.
- **Password recovery runs on the username.** Several guests may share one sponsor email, so recovery never looks up by email.
- **One chair per person.** The person picks it at registration (guests inherit the sponsor's chair). A group admin's scope is simply their own chair, so no chair assignment exists anywhere any more.
- The **head admin** can set every balance, and a new **group balance** tracks money group admins collected versus handed over.
- Mails are sent through the admin's own mailbox over SMTP.
- Forgot-password is now part of the plan (it was an optional extra).

## 0. Decisions and assumptions

Your decisions (kept from before): TOTP step-up with a fixed 5-minute unlock window; the open site is visible to any verified, signed-in user; no existing profiles to migrate.

Assumptions. They shape the design, so please veto any you disagree with:

- **A1 Two names per account.** `username` is unique, case-insensitive and used only to sign in and recover. `display_name` is what everyone sees on the site, need not be unique, and gets a "(2)" style suffix when two accounts share it. Usernames that equal a CLI admin's username are refused.
- **A2 Members and guests.** A member has a verified TUM email of their own. A guest has no email; a verified member vouches for them (`sponsor_id`). Only members can sponsor, and only members can become group admins.
- **A3 Recovery address.** For a member it is their email; for a guest it is the sponsor's email. The mail names the account, so a sponsor with several guests knows which one it is for, and forwards the link to the right person.
- **A4 The access code gate is removed.** Email verification (members) or sponsor approval (guests) is the barrier. `ACCESS_CODE` is no longer required.
- **A5 Group admin** is a promoted member. Scope is that member's own chair. Several group admins per chair are allowed. A group admin cannot change their own chair (the head admin removes the role first) and cannot change their own balance.
- **A6 Head admin** = the global admin created by CLI. Unchanged login credentials; first login enrols TOTP once, later logins are password only.
- **A7 Balance-changing actions** (all need the TOTP step-up): payment or correction, adjustment, reversal, merge, "set balance", and recording money received from a group admin. Price changes, deactivation, chair changes and role assignment do not.
- **A8 "Set balance"** for the head admin means: enter the target balance; the app books the difference as a correction entry. The ledger stays append-only, nothing is overwritten.
- **A9 Group balance** is per group admin, rolled up per chair: money that admin collected (cash payments they recorded) minus money the head admin recorded as received from them. It is derived from the ledger, never stored as a free field.
- **A10 The open site shows** display name, chair, balance in words, shots (month and total), full event and payment history (date, shots, price, amount), the group admins' names per chair and the group balances. It never shows emails, usernames, password data, sessions, audit entries, IPs, notes, or which admin recorded an entry.
- **A11 Sign convention.** Internally `balance = consumed - paid`, positive means the user owes. The UI says "You owe 3,50" or "Credit 2,00", never a minus sign.
- **A12 Allowed member email domains:** `tum.de`, `mytum.de`, `*.tum.de` (configurable). Different aliases of one person can't be detected; admins can merge duplicates.
- **A13** I read "a user who gave guest accounts" as "a member who sponsored guest accounts". Please correct me if that was meant differently.

## 1. Accounts

### Member registration

1. `/register` offers "I am a member" and "I am a guest".
2. Member form: username, display name, chair (active chairs), TUM email, password twice, privacy acknowledgement.
3. A row goes into `pending_registrations` (kind, fields, Argon2id hash, SHA-256 of a random 256-bit token, 24 h expiry). No user exists yet.
4. The app mails `/verify/{token}` to the TUM address. The response page is identical whether or not that email already has an account.
5. `GET /verify/{token}` shows a confirm page and writes nothing (mail scanners prefetch links; same rule as the scan flow). `POST` creates the member, signs the browser in, and consumes a pending coffee if this browser holds one.
6. The username's uniqueness is checked at the form and again at confirmation; whoever confirms first gets it, so nobody can squat a name with an unconfirmed request.

### Guest registration

1. Guest form: username, display name, password twice, privacy acknowledgement, and the **sponsor's email address** (must pass the TUM domain check). There is no search and no member list. The chair is inherited from the sponsor.
2. The app looks the address up among verified members. The guest always sees the same page ("if this address belongs to a registered member, a request was sent; ask them to check their inbox and spam folder"), so the form cannot be used to find out who is a member. If there is a match, a pending registration is created (7-day expiry) and a mail goes to the **sponsor's email**: who is asking (display name, username), what it means ("you vouch that this person uses the coffee machine of your institute"), and a link. If there is no match, nothing is sent (this also keeps the admin mailbox from mailing strangers).
3. `GET /verify/{token}` shows the guest's details with **Approve** and **Reject**. Only the POST acts. The sponsor does not need to be logged in; the link is the capability.
4. Approve creates the guest account (`sponsor_id` recorded). Reject deletes the request. Until approved the guest cannot sign in, and the page says so.
5. Abuse limits: at most 5 open requests per sponsor address, 3 requests per hour per IP, and the global mail cap below.
6. If a sponsor leaves or their mailbox is gone, the head admin can assign a new sponsor to a guest (audited).

### Sign-in and recovery

- `/login`: username and password. One generic failure message, a dummy hash check for unknown usernames, rate limit 5 failures per 15 minutes per username+IP plus a per-IP cap (DB-backed). Success issues a fresh session cookie, so a lost cookie is replaced by signing in.
- `/forgot`: enter the **username**. The page always answers "if the account exists, a mail was sent". The mail goes to the member's own email, or to the guest's sponsor. It names the account and carries `/reset/{token}` (1 hour, single use, only the hash stored).
- `GET /reset/{token}` shows the form, writes nothing. `POST` sets the new password, consumes the token, and revokes all of that account's sessions. The user then signs in normally.
- Limits: 3 reset requests per hour per username, 10 per hour per IP, 6 per hour per recipient address (protects sponsors from mail bombing).
- Account page: change password (revokes other sessions), edit display name and chair (audited; blocked for group admins, see A5).
- Passwords: minimum 10, maximum 128, must not equal the username or the email local part. One shared `services/passwords.py` with the existing Argon2id parameters.
- Mails are plain text only; names are stripped of newlines before they reach headers.
- Removed: access gate, `/join`, `/profiles`, profile selection, the "Is it you?" prompt, admin-created visitor accounts and invite links.

### Mail through the admin's account

**Server and transport**

- `SMTP_HOST=postout.lrz.de`; `SMTP_SECURITY=starttls` with port 587 (default) or `ssl` with port 465. The client uses `smtplib` with a default SSL context: certificate chain and hostname are always verified, TLS 1.2 minimum, no option to turn verification off. Login is only attempted after the channel is encrypted, so the password never travels in clear. If TLS cannot be established, the send fails; there is no plaintext fallback.
- Production backend is `smtp`; `console`, `memory` and `file` exist for development and tests only, and production refuses them.
- Load is low, so mails are sent in a background task right after the commit, with no queue. A failure is mapped to a safe category (`connect`, `tls`, `auth`, `recipient_rejected`, `timeout`, `other`), logged without any credential, and the user sees "could not send, try again later".
- `MAIL_MAX_PER_HOUR` (default 30) caps total sending so the mailbox is not flagged. Messages are plain text with `Auto-Submitted: auto-generated`, `MAIL_FROM` set to the mailbox address, and no user-controlled text in headers beyond a newline-stripped display name.

**Mail login: asked for during admin setup, stored securely**

- New interactive commands: `python -m app.cli setup` (one guided run: create the head admin, enrol TOTP hint, mail login, first price, test mail; each step also exists alone) and `python -m app.cli setup-mail`. They ask for the SMTP username and password with a hidden prompt (`getpass`). There is no `--password` option, so the password never appears in shell history or process lists; `--password-stdin` exists only for scripted installs. In Docker: `docker compose run --rm -it app python -m app.cli setup-mail`.
- Storage: one file in a dedicated `secrets` volume, mounted only into the app container, directory mode 0700, file mode 0600, written atomically and owned by the non-root app user. Content is encrypted with Fernet (`cryptography`), key derived from `SECRET_KEY`. This protects against a leaked volume snapshot or an accidentally shared file; it does not protect against someone who already controls the running server, which no scheme can.
- It is **not** in `.env`, the compose file, the image, the SQLite database, the backups (`backup.sh` backs up only the database volume; the restore guide says to re-run `setup-mail`), logs, error pages, the audit log, or any admin page. Changing `SECRET_KEY` makes the file unreadable, with a clear error telling the operator to re-run `setup-mail`.
- The head admin page shows only "mail configured: yes/no, user `c***@lrz.de`, last send OK / last failure category and time". It never displays or accepts the password, and group admins cannot see it. If mail is not configured, the dashboard shows a banner and registration and recovery pages say "temporarily unavailable" instead of collecting data that cannot be verified.
- Other commands: `mail-status` (same information as the page), `test-mail ADDRESS` (sends one real message through the configured server), `clear-mail` (deletes the stored login).
- Recommendation: use a dedicated or functional mailbox if TUM/LRZ offers one, rather than a personal account, and an app or service password if available. The password is then easy to rotate by re-running `setup-mail`.

## 2. QR codes

- Four permanent codes, produced by the admin QR page and `cli qr`: Register `/register`, Single `/coffee/single`, Double `/coffee/double`, Website `/overview`.
- Scanning a shot QR without a session stores the pending coffee (existing `pending_actions`, 1 h) and shows `/login` with a plain "Create account" link. After login in that browser the coffee is recorded atomically as today.
- Registration never records a coffee. If a member verifies in another browser (mail app), a pending coffee from before registering is dropped after 1 h and the user scans again.

## 3. Open website (`/overview`)

Requires a valid user session; anonymous visitors go to `/login` and are returned via a pending action of kind `view_site` (no redirect parameter). Server-rendered, mobile-first, usable without JS; sorting and filtering via query parameters; `Cache-Control: private, no-store`.

| Page | Content |
| --- | --- |
| `/overview` | Totals (shots, consumed, paid, owed, credit), current price, this month, 12-month trend, per-chair summary |
| `/overview/people` | All accounts: display name (+suffix), chair, shots this month, shots total, balance in words. Search ("muller" finds "Müller"), chair filter, sorting |
| `/overview/people/{id}` | One person's complete consumption and payment history, reversals marked |
| `/overview/chairs` | Per chair: members, group admin names, owed and credit totals, collected / handed over / still held by the group |
| `/overview/prices` | Price history |

- New read-only `services/overview.py`: grouped queries over the `effective_users` view, one query per page, month bounds from `timeutil`.
- Deactivated users are hidden unless their balance is non-zero, then marked "inactive".
- Admins see an "Edit balance" button on a person page, linking to `/admin/users/{id}`.
- The privacy page and the registration checkbox are rewritten: name, chair, balance, history and group balances are visible to every verified account.
- No public JSON API.

## 4. Admin: roles, balances, step-up 2FA

**Roles.** On a member's detail page the head admin sees one button, "Make group admin" / "Remove group admin". No chairs to pick; scope is the member's own chair. Guests cannot be promoted. Demotion revokes the admin sessions and warns if the person still holds group money (the balance stays visible). `/admin/admins` lists role holders. `admin_chairs` and the `set-admin-chairs` command are dropped. The last global admin cannot be removed. All changes are audited.

**Authentication.** `admin_users.user_id` links a group admin to their account. At `/admin/login` the identifier is a CLI admin username or a group admin's account username; the password is the matching one. A normal user cookie alone never reaches `/admin`; a password login creating the `coffee_admin` session (12 h, Path=/admin) is required. First admin login enforces one-time TOTP enrolment (QR, secret, 8 recovery codes); TOTP reset stays CLI-only.

**What each role can do with money**

| Action | Group admin (own chair only) | Head admin |
| --- | --- | --- |
| Record payment / correction, adjustment, reverse an event | yes | yes, everyone |
| Set balance to a target value | no | yes, everyone |
| Record money received from a group admin | no | yes |
| Own balance | no | yes |

**Step-up for balance changes.**

- The entry form posts to a read-only confirm page (person, amount, resulting balance) carrying an HMAC-signed payload and a one-time nonce. The confirm POST executes.
- The confirm page asks for a TOTP or recovery code only if `admin_sessions.stepup_until` has passed. A correct code sets `stepup_until = now + STEPUP_WINDOW_SECONDS` (300, fixed) and runs the action, so several payments in a row need one code. Replay of a code within 120 s is rejected; failures count toward the admin rate limit.
- Enforced in a route dependency `require_stepup`, not just in the template. Audited, including whether a fresh code or the open window authorised it.
- `payment_events.idempotency_key` (from the nonce) prevents double booking.

**Group balance and remittances.**

- New append-only table `group_remittances`: group admin, chair (at event time), signed amount, recording head admin, optional `correction_of_id` (at most one correction per entry), idempotency key, note, timestamp.
- Derived: `group_balance(admin) = SUM(cash payments recorded by that admin) - SUM(remittances from that admin)`. The chair figure is the sum over its group admins.
- Only payments of kind `cash` count as collected. The head admin's "set balance" entries are kind `correction` (bookkeeping, no cash) and never touch group balances.
- Head admin page `/admin/groups`: per group admin the collected, handed-over and still-held amounts, a form "Received X from <group admin>" (step-up applies), and the entry list. The dashboard gets a "held by groups" tile. CSV export of group balances.
- A negative balance (more handed over than collected) is allowed and flagged.

## 5. Scan result page

`/coffee/done/{event}` and `/account`:

- Headline in words: "Outstanding: X" or "Credit: X".
- "Shots this month": net `SUM(quantity)` of the user's consumption events in the current local month (reversals net out). New `ledger.get_month_shots(db, user_id, now=None)`.
- Kept: what was just recorded, undo within the window, links to account and site.

## 6. Schema (one new Alembic revision, owner A)

- `users`: `username`, `username_normalized` (unique), `account_kind` (`member` | `guest`), `email` (members only), `verified_at`, `sponsor_id` (FK users, guests only), `password_hash`. Partial unique index on `email` where not null. CHECKs: member needs email and no sponsor; guest needs a sponsor and no email; both need a password hash. `chair_id` stays the single chair.
- New: `pending_registrations` (kind, username, display name, chair, email or sponsor, password hash, token hash unique, expires_at), `password_reset_tokens` (user, token hash unique, expires_at, consumed_at), `group_remittances`.
- `admin_users`: `user_id` (unique, nullable FK); `password_hash` nullable; CHECK that role `chair` has a user link. Drop `admin_chairs`.
- `admin_sessions`: replace `totp_verified` with `stepup_until`.
- `payment_events`: add `kind` (`cash` | `correction`, default `cash`) and `idempotency_key` (unique, nullable).
- `pending_actions.kind`: add `view_site`.
- With no data, squashing into the initial migration is possible, but an additive revision is safer and keeps `alembic check` clean.
- `authz.visible_chair_ids` for a group admin becomes the set containing their user's chair.
- `check-ledger` gains: group balance consistency, remittance corrections unique and valid, correction-kind payments never counted as collected, and a note on negative group balances.

## 7. Configuration, tests, docs

**Config added:** `MAIL_BACKEND` (`smtp` | `console` | `memory` | `file`), `SMTP_HOST` (default `postout.lrz.de`), `SMTP_PORT` (587), `SMTP_SECURITY` (`starttls` | `ssl`), `MAIL_FROM`, `MAIL_FILE_DIR` (dev/e2e only), `SECRETS_DIR` (default `/secrets`), `MAIL_MAX_PER_HOUR`, `ALLOWED_EMAIL_DOMAINS`, `VERIFICATION_TTL_HOURS` (24), `GUEST_APPROVAL_TTL_DAYS` (7), `RESET_TTL_MINUTES` (60), `PASSWORD_MIN_LENGTH` (10), `STEPUP_WINDOW_SECONDS` (300), `BALANCE_TOTP_REQUIRED`. Removed: `ACCESS_CODE` requirement, `ADMIN_TOTP_REQUIRED` (renamed). Production refuses a mail backend other than `smtp`.

**Tests to add or change**

- Member registration: domain rejected, identical response for known and unknown email, GET verify writes nothing, expiry, replay, double POST creates one user, hashes only in the DB, username race resolved at confirmation.
- Guest registration: mail goes to the sponsor (captured), approve and reject, no sign-in before approval, identical page for a member's address, a non-member address and a non-TUM address (and no mail in the last two cases), per-sponsor and per-IP caps, chair inherited, guest cannot be promoted or sponsor.
- Recovery: member mail goes to own email, guest mail goes to the sponsor, two guests of one sponsor each reset only their own account, unknown username gives the same page, rate limits per username, IP and recipient, sessions revoked after reset, token single use.
- Login: generic failure, rate limit, session rotation, pending coffee recorded once, usernames equal to a CLI admin's username refused.
- Roles: promotion needs a member, scope equals own chair, chair change blocked for group admins, demotion revokes sessions, user cookie alone cannot reach `/admin` (route enumeration test updated).
- Step-up: no code means no write, wrong code, replay, window expiry, recovery code, tampered payload, double submit books once, self-balance blocked, group admin cannot set balance or record remittances.
- Group balance: cash payments by a group admin count, correction entries do not, remittance reduces the held amount, correction of a remittance, rollup per chair, site shows the same numbers as the admin page.
- Site: anonymous redirected; a seeded sentinel email, username, hash, note and IP never appear in any site response; month boundary in Europe/Berlin; sign wording.
- Playwright e2e rewritten: register QR, member mail (file backend), verify, scan, success page with month shots and balance, rescan; guest path with sponsor approval; forgot password.
- Delete access-gate and profile-selection tests.

### 7b. How the email logic is tested (simulated, no real mail needed)

The mail code sits behind one small `Mailer` interface, so there are two independent layers, both runnable offline in CI:

1. **Logic layer (in-memory mailbox).** Tests use the `memory` backend. After a registration, guest request or reset request, the test reads the captured message, extracts the link from the plain-text body, and drives the real HTTP flow with it: GET shows the page and writes nothing, POST confirms, replays and expired tokens fail, the right recipient got it (member's own address, or the sponsor's), rate limits trigger. This covers every flow in sections 1 and 4 without any network.
2. **Protocol layer (fake SMTP server).** A real `smtplib` client talks to a local `aiosmtpd` server on random ports (Python 3.12+ no longer ships `smtpd`). A test certificate is generated on the fly. Cases:
   - STARTTLS on the 587-style port and implicit TLS on the 465-style port deliver a message after AUTH.
   - Wrong password gives the `auth` category; untrusted certificate or hostname mismatch is refused (no fallback); connection refused and timeout map to safe errors; a 550 recipient rejection is handled; the server refuses AUTH in clear and we never attempt it.
   - Message content: plain text, `Auto-Submitted` header, correct From/To, the link present, a display name containing CR/LF cannot inject headers.
   - Hourly cap and per-recipient cap block the send before it reaches the server.
3. **Credential handling tests.** The stored file has mode 0600 in a 0700 directory, the password does not appear in its bytes, logs (captured), `repr(settings)`, error pages, audit rows, a `backup.sh` run, or any admin page; a wrong `SECRET_KEY` gives the clear "re-run setup-mail" error; `--password` is not an accepted option.
4. **Browser e2e.** The live app runs with `MAIL_BACKEND=file`; Playwright reads the `.eml` file written to the temp directory, opens the link, and finishes the flow for member registration, guest approval and password reset.

First spike (already done in this sandbox): a fake relay with STARTTLS, implicit TLS and AUTH passed 11 of 11 checks, namely both transports delivering, wrong password, untrusted certificate on both transports, AUTH in clear refused, recipient rejected, connection refused, header injection blocked, and the password never appearing in a delivered message. The throwaway script is `smtp_spike.py` in the session scratch area and is not part of the project.

**What a simulation cannot show:** whether LRZ accepts a login from this server, accepts the chosen `From` address, allows automated mail from that mailbox, applies a sending quota, or files the mails under spam. That is covered by a short post-deployment checklist: run `setup-mail`, then `test-mail` to your own TUM address, check headers and the spam folder, run one real guest request and one password reset, and read `mail-status`.

**Docs:** README (the verbatim limitation sentence must change: identity is now a verified TUM email or a sponsor's vouching, plus a password, and still no proof of real-world identity), privacy page, `.env.example` including the SMTP section, ARCHITECTURE.md, PROGRESS.md, ACCEPTANCE.md.

## 8. Work packages and order

| # | Package | Owner | Depends on |
| --- | --- | --- | --- |
| 1 | Schema revision, models, config, `passwords.py`, month shots, group balance and overview queries, authz by own chair | A | none |
| 2 | Mail service (`Mailer`, smtp/memory/file backends, encrypted credential store), member and guest registration, verification and approval, login, forgot/reset, rate limits, pending-action changes, removal of the gate | B | 1 |
| 3 | User routes, templates, strings: register (member/guest), verify and approve pages, login, forgot/reset, scan result, account, password change | U | 2 |
| 4 | Admin: login for linked group admins, TOTP enrolment, step-up dependency and confirm pages, role button, `/admin/groups` and remittances, set balance, sponsor reassignment, mail status on the dashboard, QR page with 4 codes, CLI (`setup`, `setup-mail`, `mail-status`, `test-mail`, `clear-mail`, drop `set-admin-chairs`) | M | 1 (parallel with 2; needs the credential store from 2 for `setup-mail`) |
| 5 | Open site: routes, templates, `overview.py`, CSS, admin deep links | U or a new agent W | 1 |
| 6 | Ops: `.env.example` (no mail login in it), compose `secrets` volume, backup script excludes it, README setup and post-deployment mail checklist, privacy page, smoke script | O | 2 to 5 |
| 7 | Tests and e2e (each owner for their package), then ledger audit, security review, acceptance run | all, then orchestrator | 1 to 6 |

Milestones: M4 packages 1 and 2; M5 packages 3 and 4; M6 packages 5 to 7. Each ends with all tests green and PROGRESS.md updated.

## 9. Definition of done (v2)

1. Members register with username, password and a verified TUM email; non-TUM addresses are refused. Guests register with a sponsor who approves by mail.
2. Password recovery works by username and reaches the right inbox: own email for members, the sponsor's for guests, and each guest of one sponsor recovers only their own account.
3. Each person has exactly one chair; no admin screen assigns chairs; a group admin acts only within their own chair.
4. Register, Single, Double and Website each have their own QR code; the registration QR never records a coffee.
5. Any verified, signed-in user can open the site; no email, username, hash, note or IP appears in any page.
6. The head admin can set every balance and record money received from group admins; the group balance shows collected, handed over and held, and matches on the admin page and the site.
7. Every balance-changing action requires TOTP inside the unlock window and nothing else asks for TOTP; nothing is written without it.
8. A shot scan shows outstanding debt or credit in words plus shots this month.
9. Mail goes out through `postout.lrz.de` with verified TLS; the mail login is entered at setup, stored encrypted outside the database and backups, and appears in no log, page or backup.
10. Tests pass (including the fake-SMTP protocol tests), `alembic check` is clean, `check-ledger` passes, `pip-audit` is clean, e2e passes. The real-server check is the post-deployment mail checklist, not part of the automated tests.

## 10. Open items and risks

- **Mailbox sending:** you will enter the login at deployment. Confirm with TUM/LRZ that automated mail from that mailbox is allowed and that the `From` address matches the account. The cap, `test-mail` and the dashboard banner limit the risk. If the password changes, mails stop, and the banner and `mail-status` show the failure category.
- **Restores:** because the mail login is deliberately not in backups, a restore onto a new server needs `setup-mail` again.
- **Sponsor workload and trust:** a sponsor receives every reset mail of their guests and could use such a link themselves; that is accepted as part of vouching. A reassign action covers sponsors who leave.
- **Sponsor typos:** a guest who mistypes the sponsor's address gets the same neutral page and no mail; the page tells them to double-check the address and the spam folder. This is the price of not revealing who is a member.
- **Privacy:** every verified account sees everyone's balance, history and group balances. Worth a short word with the department's data protection contact before launch (I am not a lawyer).
- **Duplicate people:** different TUM aliases can create two accounts for one person; admins can merge (step-up applies).

# Task 3.1 - Registration, guest flow, login/recovery pages, strings

Status: done. Full suite (e2e file excluded) 1690 passed, 0 failed; e2e (Chromium) 1 passed. Baseline 1633 incl. e2e.

## What changed
- `/register`: visible choice "I am a member" / "I am a guest" (links, GET `?kind=guest`, no JS). Member form unchanged (POST `/register`); guest form (username, display name, password twice, sponsor e-mail, privacy) posts to the NEW `POST /register/guest`. Page text: guests need a member to vouch, members need a verified TUM address.
- Guest submit: `registration.begin_guest`; the username-taken `Conflict` is caught INSIDE `write_session()` (probe hit commits, 10/15 min budget shared with the member form); always the neutral page `register_guest_sent.html` (identical bytes for member, stranger, full sponsor); mail to the sponsor in the background only when a request was stored. Sponsor-field errors use `error_sponsor_*` keys.
- `/verify/{token}`: guest tokens render Approve/Reject (GET writes nothing). Same `POST /verify/{token}` route: form field `action=approve|reject` selects the guest branch (no new path; log redaction unchanged), no field = member confirm. Messages: success ("X can now sign in with the username Y"), rejected, dead link (400), sponsor inactive (403), username taken (409, link not burnt), failed (400). No login or cookie for the sponsor.
- "Temporarily unavailable" (L2): `user_views.mail_unavailable()` = backend `smtp` and `mail_credentials.status().configured` false. Then GET and POST of `/register`, `/register?kind=guest`, `/register/guest`, `/forgot` answer 503 `user/unavailable.html` and collect/write nothing. memory/console/file stay available. `/login`, `/privacy` unaffected.
- `recovery._recovery_address` deleted; `recovery.request_reset` uses `registration.recovery_address(user, db)` (a guest's sponsor must now also be verified; same neutral page when the sponsor is gone, tested).
- Login: view_site redirect to `/overview`, "Create account" link and anonymous-scan redirect already existed from 2.5; now pinned by tests (no redirect parameter honoured).
- Privacy page and the registration checkbox rewritten per A10 (visible to every verified signed-in account: name, chair, balance, history, group admins, group balances; never e-mail, username, password data, sessions, IPs, notes, recorder). Retention and contact kept. New keys `user.privacy.never_title|never|admins`.
- `message.html` takes `args` (t() parameters) and an `ok` tone; CSS `.choice` in `static/user.css`.

## Tests
- New `tests/test_user_guest_web.py` (45). Updated `tests/test_audit_security_authz_csrf.py` (inventory and CSRF matrix include `/register/guest`), `tests/test_user_account.py` (string-key families, `/register?kind=guest` in the markup/CSP page list).

## Later tasks must know
- 6.1: README privacy wording can link the new privacy text; the page promises overview facts (group admins, group balances) that 5.1/5.2 build. Keep the 5.2 sentinel test on "no e-mail/username/password data shown".
- GET `/verify/<guest token>` for a guest whose sponsor became inactive shows the generic dead-link page (peek returns None); only a POST of approve shows "you can no longer vouch".
- Admin dashboard banner for "mail not configured" is not part of this task.

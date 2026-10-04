# Task 5.2: person page, chairs, prices, privacy sentinel crawl

Status: done. Commit "site: person, chairs, prices pages and privacy sentinel crawl (task 5.2)".
Full suite incl. e2e: 1764 passed, 0 failed, 0 errors (baseline 1728).

## What changed
- `app/web/routes_overview.py`: `GET /overview/people/{person_id}`, `GET /overview/chairs`, `GET /overview/prices` (GET only, same `_anonymous` / `_page` helpers, `Cache-Control: private, no-store`).
- `app/services/overview.py`: one addition, `can_edit_balance(db, viewer_user_id, person: PersonHistory) -> bool`.
- `templates/site/person.html`, `chairs.html`, `prices.html`; `static/site.css` (history row styles); `app/strings_site.py` (`site.person.*`, `site.chairs.*`, `site.prices.*`).
- Tests: `tests/test_site_pages.py` (31), `tests/test_site_sentinel.py` (4, the crawl), `tests/test_core_overview.py` (+1), `tests/test_site_overview.py` (route enumeration now lists all five routes).

## Behaviour
- Person page: name (with " (2)" suffix), chair, inactive badge, balance in words, shots this month and total, consumption table (date in Europe/Berlin, shots, unit price, amount, type Coffee / Reversal / Reversed) and payment table (Payment / Paid back). Reversals and paid-back amounts are shown with absolute values and a word, never a minus sign. Newest first, complete (no pagination). No admin, note or collector is shown.
- 404 (same plain page, `Cache-Control: private, no-store`) for malformed, unknown, hidden (inactive with zero balance) AND merged ids. Decision: a merged id is not a person of its own (the site never lists it), so it is 404 rather than a redirect to the target; the target page counts the merged history.
- "Edit balance" (links to `/admin/users/{id}`) only if the signed-in USER account is linked to an ACTIVE admin row of role chair and its chair equals the person's chair. Extra rule: never on one's own page (the ledger refuses own-account postings). Head admins created by the CLI have no user account: they use `/admin` directly and never see this button; the admin cookie (Path=/admin) is not a site session (tested: an admin cookie alone is redirected to /login).
- Chairs page: one card per listed chair (same chair list as the overview): members, current group admin names (active role-chair admins only; a former group admin is not listed), owed, credit, collected, handed over, held. Group money comes from `groups.chair_rollup` through `overview.chairs_overview`; chairs without group money show 0. Held is shown as absolute value plus the badge "More handed over than collected" (same as `/admin/groups`); collected and handed over use the same `|money` filter as the admin page. Test compares with `groups.chair_rollup` and the HTML of `/admin/groups` (per-chair table) for the same data.
- Prices page: effective-from (Berlin time) and price, newest first, badges "current" / "scheduled" (future-dated).

## Sentinel crawl (`tests/test_site_sentinel.py`)
Seeds sentinels for e-mail, username, hash, session token (raw and its hash), audit metadata, IP, payment, consumption and set-balance notes, head admin username and password hash, group admin account username and e-mail. Crawls from `/overview` by following every `/overview*` link (page size patched to 2 so pagination exists; sort, chair filter, every person page; plus search variants) and checks body and headers of each response, then the 404 pages (unknown, malformed, hidden, merged, unrouted, a path containing a sentinel), the anonymous redirects, and a group-admin session. Mutation checked: an injected `@tum.de` is caught. A group admin's display name is shown on the chairs page by design (current group admins); the test asserts it is not on the page of a person whose payment they collected.

## Later tasks must know
- Edits outside owned files: none.
- Chairs page "collected" / "handed over" can show a minus sign only if a chair's collected total is negative (kept identical to the admin page).
- README privacy wording (6.1): the pages now exist as the privacy page promises.

## Known-broken
- None.

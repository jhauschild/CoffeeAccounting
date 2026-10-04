# Task 5.1: open site `/overview` and `/overview/people`

Status: done. Commit "site: overview and people pages (task 5.1)".

## What changed
- `app/web/routes_overview.py` (new, included in `app/main.py`): `GET /overview`, `GET /overview/people`. Read-only, GET only.
- `app/strings_site.py` (new, merged in `app/strings.py`): keys `site.*` (nav labels for all five links, balance wording, page texts).
- `templates/site/` (`base.html` with the nav bar, `overview.html`, `people.html`, `_macros.html::balance`), `static/site.css`.
- `app/services/overview.py`: one addition, `chair_choices(db, now=None) -> ((chair_id, short_name), ...)` for the chair filter (plain tuples, no new dataclass; the sentinel test checks it).
- Tests: `tests/test_site_overview.py` (see pytest; 37 with parametrization); `tests/test_core_overview.py` sentinel test extended for `chair_choices`.

## Behaviour
- Auth: `deps.current_user`. Anonymous: a `view_site` pending action is created (`pending.create_view_site_pending`) and the cookie set, 303 to `/login` (no parameter). If the browser already holds a live pending action (e.g. a waiting coffee) nothing is created or overwritten. No other write.
- Every response (also the redirect) carries `Cache-Control: private, no-store`.
- Query parameters: `q` (whitespace collapsed, 120 chars), `chair` (UUID of a listed chair, anything else = all chairs), `sort` (name, balance, shots_month, shots_total; else name), `page` (digits only, up to 6 digits, else 1; the service clamps to the last page). Page size is `routes_overview.PAGE_SIZE` (50, tests patch it).
- Balance wording through `t("site.balance.owes|credit|even", amount=...)` fed from `overview.balance_label`: "Owes €X", "Credit €X", "Even". Shots and amounts shown on the site are floored at 0 (a reversal booked in a later month can make a month figure negative in the service); no minus sign anywhere.
- Trend: inline SVG (rect attributes + CSS classes only) with `role="img"`, `<title>` per bar, plus the numbers as an HTML table in an open `<details>`. No script, no style attributes.
- People rows link to `/overview/people/{id}` (task 5.2 builds it). Nav links to `/overview/chairs`, `/overview/prices` (5.2) and `/account`.

## Later tasks must know
- 5.2: reuse `templates/site/base.html` (needs `nav_items`, `nav_current` in the context; `routes_overview._page(request, template, context, nav_current)` adds them and the Cache-Control header, and `_anonymous(request)` is the anonymous handler to call first in every route). Nav keys: overview, people, chairs, prices, account. Strings live in `strings_site.py`; 5.2 may append keys there.
- The login redirect after a `view_site` pending action is the user-routes task's job (already in `routes_user._signed_in`).
- Anonymous GETs each create a pending row only when the browser has no live pending cookie; a bot without cookies creates one row per request (purged by `purge-expired`). A rate limit could be added if that matters.

## Known-broken
- None.

# Architecture contract

Source of truth for requirements: `docs/PROMPT.md` (section numbers below refer to it). This file fixes module boundaries, file ownership and service interfaces so several agents can work without colliding. Python 3.12+ (3.13 is installed in the build sandbox; code must run on both). Use `/home/claude/venv/bin/python`.

## Layout and ownership

Owners: **A** = core-ledger agent, **B** = core-platform agent, **U** = user-web agent, **M** = admin agent, **O** = ops agent. Only the owner edits a file. Need a change in a file you don't own? Append a request to `docs/status/requests.md` (who, file, what, why) and carry on.

```
app/
  config.py            A  Settings (pydantic-settings), production validation (§9, §11)
  db.py                A  engine, SQLite pragmas (WAL, FK, busy_timeout), read_session(), write_session()
  models.py            A  ALL tables, including admin/auth/audit/rate-limit tables (see below)
  money.py             A  format_money(cents), parse_money(str)->cents
  timeutil.py          A  utcnow(), to_local(), local_day/week/month bounds
  services/
    prices.py          A
    ledger.py          A  record_coffee, undo, admin reverse/adjust/payment, totals
    users.py           A  normalize_name, create/search/update/deactivate/merge, effective-user helper
    chairs.py          A
    audit.py           A
    authz.py           A  scope checks for admin actors
    checker.py         A  check-ledger logic
    sessions.py        B  user sessions (hash, issue, resolve, revoke, rotate)
    pending.py         B  pending_actions
    onboarding.py      B  register / select profile (+ consume pending action) in ONE transaction
    gate.py            B  access-code check, signed gate cookie
    ratelimit.py       B  DB-backed limiter
    admin_auth.py      M  admin accounts, passwords (Argon2id), TOTP, admin sessions, login limiter use
    stats.py           M  dashboard + user-table queries
    exports.py         M  CSV (injection-safe)
  web/
    middleware.py      B  security headers/CSP/HSTS, request-size limit, trusted-proxy IP
    deps.py            B  FastAPI deps: db, current user session, csrf, client IP
    tokens.py          B  signed scan token, CSRF tokens
    routes_user.py     U  (B creates an empty stub `router`)
    user_*.py          U  any helper modules
    routes_admin.py    M  (B creates an empty stub `router`)
    admin_*.py         M
    health.py          B  /healthz, /readyz
  strings.py           B  t(key, **kw); merges strings_user + strings_admin + strings_common
  strings_common.py    B
  strings_user.py      U  (B creates empty dict)
  strings_admin.py     M  (B creates empty dict)
  main.py              B  create_app(); includes routers from routes_user, routes_admin, health
  cli.py               A  argparse dispatcher; commands: check-ledger, set-price, purge-expired; calls cli_admin.register()
  cli_admin.py         M  (A creates stub register(subparsers)); commands: create-admin, set-admin-chairs, reset-admin-password, reset-admin-totp, disable-admin, qr
templates/
  base.html            B  blocks: title, head_extra, content, scripts_extra; local CSS only
  user/                U
  admin/               M
static/
  app.css              B  mobile-first base styles
  user.css, scan.js, user/   U
  admin.css, admin/    M
migrations/            A  ONLY A edits migrations (single Alembic head). A creates the whole schema up front.
tests/
  conftest.py, factories.py   A (B may append fixtures at the end of conftest in its own section)
  test_core_*.py       A      test_platform_*.py   B
  test_user_*.py, test_e2e_*.py   U      test_admin_*.py   M
Dockerfile, docker-compose.yml, .dockerignore, .env.example, scripts/, deploy/, README.md   O
docs/                  orchestrator (agents may write only docs/status/<their-name>.md)
```

## Schema (all created by agent A in one initial migration; names are final)

`chairs`, `users`, `prices`, `consumption_events`, `payment_events`, `user_sessions`, `pending_actions`, `admin_users`, `admin_chairs`, `admin_sessions`, `rate_limit_events`, `audit_log`. Columns for chairs, users, prices, consumption_events, payment_events, and every CHECK/UNIQUE are in PROMPT §4. Additional tables:

- `user_sessions`: id, user_id, token_hash (unique), created_at, last_seen_at, expires_at, revoked_at.
- `pending_actions`: id (random opaque, unique), kind, nonce (unique), created_at, expires_at, consumed_at.
- `admin_users`: id, username, username_normalized (unique), password_hash, role (`global`|`chair`), active, totp_secret (nullable), totp_enabled, recovery_codes (JSON list of hashes), created_at, last_login_at.
- `admin_chairs`: admin_id, chair_id (composite PK).
- `admin_sessions`: id, admin_id, token_hash (unique), created_at, last_seen_at, expires_at, revoked_at, totp_verified, csrf_secret.
- `rate_limit_events`: id, bucket, key, created_at (index on bucket,key,created_at).
- `audit_log`: PROMPT §7, with triggers rejecting UPDATE/DELETE.
- View `effective_users` (id → effective_id following `merged_into_id`), used by all totals.

## Transaction rules

- `db.read_session()` and `db.write_session()` are context managers yielding a SQLAlchemy `Session`. `write_session()` starts `BEGIN IMMEDIATE`, commits on success, rolls back on exception.
- Mutating service functions take `db: Session` opened by the caller with `write_session()`; they **never commit** and never open their own session. Read functions accept either.
- Routes open the session; services hold business rules; templates hold none.
- Raise typed exceptions from `app/services/errors.py` (A): `NotFound`, `Forbidden`, `UserInactive`, `NoPriceConfigured`, `AlreadyReversed`, `UndoNotAllowed`, `InvalidAmount`, `Conflict`, `RateLimited`. Routes map them to safe pages/messages.

## Service interfaces (names and meanings are final; add keyword args freely, do not rename)

```python
# prices.py
get_price_in_effect(db, at=None) -> Price | None
add_price(db, *, price_per_shot_cents, effective_from=None, admin_id, note=None) -> Price
list_prices(db) -> list[Price]

# ledger.py
@dataclass RecordResult: event: ConsumptionEvent; created: bool
@dataclass Totals: consumed_shots: int; consumed_amount_cents: int; paid_amount_cents: int; balance_cents: int
record_coffee(db, *, user_id, kind, nonce, session_id=None) -> RecordResult     # idempotent on nonce; checks active user + price
undo_coffee(db, *, user_id, session_id, event_id, now=None) -> ConsumptionEvent
latest_undoable_event(db, *, user_id, session_id, now=None) -> ConsumptionEvent | None
admin_reverse_event(db, *, admin, event_id, note=None) -> ConsumptionEvent
add_adjustment(db, *, admin, user_id, quantity, amount_cents=None, note=None) -> ConsumptionEvent
add_payment(db, *, admin, user_id, amount_cents, note=None, correction_of_id=None) -> PaymentEvent
get_totals(db, user_id) -> Totals                                              # effective-user aware
recent_consumption(db, user_id, limit=20); recent_payments(db, user_id, limit=20)

# users.py
normalize_name(s) -> str
create_user(db, *, display_name, chair_id) -> User
search_profiles(db, query, limit=50) -> list[PublicProfile]                    # name + chair only
update_profile(db, *, user_id, display_name=None, chair_id=None, actor_type, actor_id=None) -> User   # audits chair change
set_user_status(db, *, admin, user_id, active: bool) -> User
merge_users(db, *, admin, duplicate_id, target_id) -> User                     # global admin only

# authz.py
ensure_admin_can_access_user(db, admin, user_id) -> None                       # raises Forbidden
visible_chair_ids(db, admin) -> set[UUID] | None                               # None = all

# sessions.py (B)
issue_session(db, user_id, now=None) -> str raw_token                          # stores SHA-256 only
resolve_session(db, raw_token) -> tuple[UserSession, User] | None              # touches last_seen at most hourly
revoke_session(db, session_id); revoke_user_sessions(db, user_id)

# pending.py / onboarding.py / gate.py / ratelimit.py (B)
create_pending(db, kind, nonce) -> str pending_id
register_and_start_session(db, *, display_name, chair_id, pending_id=None) -> OnboardResult(user, raw_token, event|None)
select_profile_and_start_session(db, *, user_id, pending_id=None, old_session_id=None) -> OnboardResult
check_access_code(code) -> bool ; make_gate_cookie() ; verify_gate_cookie(value) -> bool
check_rate(db, bucket, key, limit, window_seconds) -> None  # raises RateLimited

# audit.py
log(db, *, actor_type, actor_id, action, target_type=None, target_id=None, metadata=None, ip=None) -> None
```

## Route ownership

- **U**: `GET /`, `GET|POST /coffee/{single|double}`, `GET /coffee/done/{event_uuid}`, `POST /coffee/undo/{event_uuid}`, `GET|POST /join`, `GET|POST /register`, `GET /profiles` (+ search), `POST /profiles/select`, `GET /account`, `GET|POST /account/edit`, `POST /account/leave`, `GET /privacy`.
- **M**: everything under `/admin`: login (password + TOTP), logout, password change, dashboard, users (list/detail/actions), chairs, prices, QR page, audit view, CSV exports.
- **B**: `/healthz`, `/readyz`, static mount, error handlers (safe 4xx/5xx pages).

## Conventions

- Money: integer cents only; format/parse via `app/money.py`. UUID primary keys (`sqlalchemy.Uuid`).
- All user-facing text through `t("key")`; add keys only to your own strings module.
- Tests run against a temp-file SQLite DB created by Alembic (never `:memory:`, never `create_all`). Run from the repo/worktree root: `/home/claude/venv/bin/python -m pytest -q`.
- No CDN or external assets. No inline JS/CSS (strict CSP).

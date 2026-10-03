# Brief 02 — user-web (agent name: `user-web`)

Dir: `/home/claude/wt/user-web` (git worktree, branch `user-web`). Read `docs/agents/00-protocol.md`, `docs/ARCHITECTURE.md`, `docs/status/core-b.md`, and PROMPT §3, §5, §8 (privacy page), §9, §12 (scan-flow tests). Use the existing services; do not reimplement ledger or session logic.

## Build (files marked **U**)

1. `app/web/routes_user.py` (+ `user_*.py` helpers) implementing every U route in the architecture exactly per PROMPT §3 and §5:
   - `GET /coffee/{kind}`: **writes nothing**; renders the tiny auto-submit page with the signed token; `Cache-Control: no-store`; no-JS fallback button.
   - `POST /coffee/{kind}`: verify token + fetch-metadata/Origin; session valid → `record_coffee` in `write_session()` → `303` to `/coffee/done/{uuid}`; replayed nonce → same redirect; no session → create pending action, set pending cookie, `303 /join`; no price configured → safe page; inactive user → clear message.
   - `/join` (access gate, rate-limited) → `/register` and `/profiles` (gated). Registration and selection call `onboarding.*` and set the new session cookie (`coffee_session`: HttpOnly, Secure in production, SameSite=Lax, Path=/, max-age = session lifetime). Pending-coffee notice on registration/selection when a pending action exists. Duplicate-name hint. Trust-based warning on the selection page. Public list shows name + chair only.
   - `GET /coffee/done/{uuid}`, `POST /coffee/undo/{uuid}` (CSRF), `/account`, `/account/edit`, `/account/leave`, `/privacy`, `/`.
2. `static/scan.js`: auto-submit only when visible and not prerendering, once only; no inline JS anywhere.
3. Templates under `templates/user/` extending `base.html`; large success indicator, shots, price, amount, local timestamp, totals (balance negative = "credit"), undo button within window, link to account. `static/user.css`.
4. `app/strings_user.py` for all texts.
5. Tests `tests/test_user_*.py` using core fixtures: the full scan-to-ledger flow per PROMPT §12 (GET writes nothing; replays; two scans → two events; refresh/Back; registration after single and after double with exactly one event; double-submitted registration; gate rules; undo variants; deactivated between page load and POST; selection on a new browser; profile edit and audited chair change; CSRF failure; cookie flags; open-redirect impossibility). Plus `tests/test_e2e_scan.py`: one Playwright (headless Chromium at `/opt/pw-browsers`) test of scan → auto-submit → access code → register → success → refresh → second scan with no prompt; if the browser cannot launch, skip with a clear reason and say so in your report.

## Done when

Your tests plus all existing tests pass in your worktree; committed on branch `user-web`; `docs/status/user-web.md` updated.

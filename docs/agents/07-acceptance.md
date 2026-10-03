# Brief 07 — acceptance (agent name: `acceptance`)

Dir: `/home/claude/wt/acceptance` (worktree, branch `acceptance`, created from merged `main` after fixes). Fresh eyes. Read `docs/agents/00-protocol.md` and PROMPT §14 (Definition of Done) and §13.

## Job: verify the Definition of Done by actually running the app

Using a real running instance (uvicorn on a temp port with a temp SQLite DB, `ENVIRONMENT=development` where https is impractical, plus one run with production settings to confirm refusal/validation), execute and record evidence (commands + short results) for each DoD item 1–10:
- migrations from empty, `create-admin`, TOTP enrollment (generate codes with `pyotp`), `set-price`, chair creation;
- full user flows with `curl`/`httpx` cookie jars **and** the Playwright e2e (headless Chromium): scan → gate → register → success → refresh → rescan; single vs double amounts; price change then scan; undo; payments; balances; chair-admin vs global-admin visibility; CSV export; QR SVG generation;
- `scripts/smoke.sh`, backup then restore round-trip on the live DB file, `docker build`/`compose config` if a daemon exists;
- the README commands: execute each one exactly as written and report any that fail or don't match reality.

## Output

Write `docs/ACCEPTANCE.md` (your only docs file besides your status file) with a table: DoD item → **VERIFIED (how)** / **NOT VERIFIED (why)** / **FAILED (repro)**. Do not mark anything verified that you did not run. Commit on your branch. Do **not** fix application code or docs outside `docs/ACCEPTANCE.md`; list defects in your report.

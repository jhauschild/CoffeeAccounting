# Brief 05 — ledger auditor (agent name: `ledger-audit`)

Dir: `/home/claude/wt/audit-ledger` (worktree, branch `audit-ledger`, created from merged `main`). You did not write this code; read it with fresh eyes. Read `docs/agents/00-protocol.md`, `docs/ARCHITECTURE.md`, PROMPT §3, §4, §16-style race list (see §12 tests).

## Job: try to break the money and idempotency invariants

Write **adversarial tests** in `tests/test_audit_ledger_*.py` (real HTTP flow plus service level, file-based SQLite, real threads) and report every failure as a finding. Probe at least:
- double-submit/replay: same nonce across users, sessions, after registration, after undo; token tampering and expiry; concurrent POSTs of one token; pending action consumed twice;
- reversal races: concurrent undo and admin reverse of the same event; reversing a reversal; reversing someone else's event; undo after the user's session was rotated; undo across price change (amount must equal original);
- price snapshot: event inserted exactly at `effective_from`; price change between GET and POST; future-dated price; adjustment amounts; amounts never recomputed anywhere (grep for places that multiply quantity by the *current* price);
- merge: totals unchanged, no event modified (compare row hashes before/after), chains, merging into a merged/inactive profile, merging a profile with active sessions, scan from a merged profile's old session;
- deactivation race: deactivate between page load and POST, between pending creation and registration;
- totals: credit balances, large numbers, negative payments/corrections, sign rules, rounding (none expected), effective-user view correctness with SQL-level spot checks;
- `check-ledger` catches each corruption you can inject via raw SQL (disable triggers/constraints in a scratch copy only).

## Output

Failing tests stay in the branch only if they demonstrate a real bug (mark with `xfail(strict=True)` and a reason); passing adversarial tests stay as regression tests. Commit on your branch. Your report lists findings as `SEV (high/med/low) — file:line — what — minimal repro test name`. Do **not** fix application code; the orchestrator assigns fixes.

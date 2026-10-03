# Protocol for every agent (read first, then your own brief)

Goal: build the coffee ledger described in `docs/PROMPT.md` following `docs/ARCHITECTURE.md`. This protocol exists so that work survives interruptions (rate limits, timeouts, lost containers) and costs as few tokens as possible.

## Rules for agents

1. **Work only in your assigned directory** (given in your task message, an absolute path). Run all commands from there. Python: `/home/claude/venv/bin/python` (dependencies already installed; do not create venvs; install extra packages only if truly needed and tell the orchestrator in your report).
2. **Resume first.** Before anything else: read `docs/status/<your-name>.md` (if it exists), run `git log --oneline -15` and `git status --short`. Continue from "Next"; never redo work listed under "Done".
3. **Commit early and often.** After every finished unit (a module, a test file, a passing fix) run `git add -A && git commit -qm "<scope>: <what>"` and update `docs/status/<your-name>.md` with three short sections: *Done*, *Next*, *Notes/Blockers*. Uncommitted work is lost work.
4. **Stay inside your files.** Edit only files you own per `docs/ARCHITECTURE.md`. Everything else: append a request to `docs/status/requests.md` and continue (stub or mock around it).
5. **Token economy.** Run tests quietly (`python -m pytest -q -x 2>&1 | tail -25`). Read files with offset/limit; do not re-read files you just wrote; do not paste file contents or long logs into your output; no running commentary. Prefer a few meaningful tests per behavior over many redundant ones.
6. **No stubs that pretend.** If something can't be done or verified (Docker daemon, browser), say so in your report; never claim it works.
7. **If a tool call fails with a rate-limit, overload, quota, or "try again later" error:** do not loop or retry more than once. Commit what you have, update your status file, and return immediately with `STATUS: INTERRUPTED`.
8. **Quality bar:** every behavior you add has a test; all tests (yours and existing) pass before you report `DONE`; no TODO placeholders in shipped code; follow the invariants in PROMPT §4 and §9 literally.

## Final report format (≤ 150 words, nothing else)

```
STATUS: DONE | PARTIAL | BLOCKED | INTERRUPTED
BRANCH/DIR: <path>   LAST COMMIT: <hash>
TESTS: <passed>/<total> (<command>)
OPEN ISSUES: <≤ 8 short lines, or "none">
REQUESTS FOR OTHER OWNERS: <or "none">
```

## Orchestrator duties (rate-limit resilience)

- State lives on disk: `docs/status/state.json` (per-agent status, attempts, last commit) and `docs/PROGRESS.md`. Update them after every agent returns.
- Concurrency ≤ 2 agents. Builders run on a mid-tier model; the core and reviewers on the strongest.
- After each phase: run the full test suite myself, merge the branch, write a `git bundle` to `/mnt/user-data/outputs/checkpoints/`, commit the bundle to the user's folder, and save `docs/PROGRESS.md` to the project.
- If an agent returns `INTERRUPTED` or a tool error mentions limits/overload: do **not** retry immediately. Schedule a resume with `send_later` (10 min → 30 min → 60 min across consecutive failures), then re-dispatch the same brief; the new agent resumes from git + its status file. After 3 failed attempts for one agent, stop and tell the user exactly where the state is.
- Never discard a worktree branch with unmerged commits.

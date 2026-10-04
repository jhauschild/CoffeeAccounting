# Orchestrator resume protocol

Any session may be killed (usage limit, container reclaimed). Nothing is lost if the work is on GitHub, so: commit and push after every wave, and make restarts automatic. Restart path: the user starts a new session with the GitHub token and the words "resume the coffee-ledger build"; that session follows this file. (An unattended hourly watchdog was NOT created: storing the token in a scheduled task prompt was refused. It can be added later if the user supplies a safer way to provide the credential.)

## 1. Setup (fresh session)
1. `TOKEN` = GitHub token from the prompt that started you. Never write it to a file, remote URL or git config.
2. `git clone https://github.com/Sydeva/CoffeeAccounting.git coffee-ledger && cd coffee-ledger && git checkout v2`; `git config user.name "Claude"`; `git config user.email "noreply@anthropic.com"`.
3. `python3 -m venv /home/claude/venv && /home/claude/venv/bin/pip install -q -r requirements-dev.txt`.
4. Read docs/status/TASKS.md, BASELINE, and the newest docs/status/task-*.md.

## 2. Lock (one orchestrator at a time)
`docs/status/LOCK` holds `<ISO UTC time> <holder>`. If it is newer than 90 minutes and you are not the holder: another orchestrator is alive, say so and exit. Otherwise take over: write LOCK, reset every task marked `doing` to `todo` (its worktree died), commit, push. Refresh LOCK (commit and push) at the start and end of every wave.

## 3. Wave loop (max 2 agents at once)
1. Choose up to two `todo` tasks whose dependencies are `done` and that touch different files. Mark them `doing`, update LOCK, commit, push (this is the claim).
2. Spawn one agent per task (Agent tool, `isolation: "worktree"`, subagent_type general-purpose; `model: "sonnet"` for tier L, default model for tier H). Prompt = docs/status/BRIEF-TEMPLATE.md + the task row + the PLAN-v2 sections it needs + the name of the file area the other agent owns. Run both in one message.
3. When both return: `git merge --no-edit <worktree branch>` for each (resolve conflicts; docs/status/task-*.md never conflict), run the full suite, compare with BASELINE, mark tasks `done` with a one-line result (or `blocked` with the reason), update BASELINE, remove the worktrees, commit, push with `TOKEN=... sh docs/status/push.sh v2`.
4. If an agent was cut off without a report, check its worktree branch (`git branch`); if it has commits, review and merge them, else reset the task to `todo`.
5. A task marked `blocked` twice is skipped; continue with the others. If only blocked tasks remain, write docs/status/STUCK.md (what, why, what is needed) and stop.

## 4. Gates
- After 2.5 (M4): full suite must be green apart from documented known-broken tests; spawn a fresh reviewer agent for tasks 1.3, 1.4, 2.2 to 2.5 (security and contract compliance) and fix findings as small tasks.
- After 4.5 (M5): reviewer for 4.1 and 4.2 (step-up must be enforced in the route dependency, not the template).
- 7.2 is the full ledger audit and security review; 7.3 the acceptance run (update docs/ACCEPTANCE.md and PROGRESS.md; say honestly what was not verified, for example Docker if no daemon).

## 5. Finish
All tasks `done` or `blocked`: write docs/status/FINAL.md (summary, verified vs not, commands), push, and report to the user. If a watchdog exists, disable it (`update_trigger` enabled=false, id in docs/status/WATCHDOG_ID).

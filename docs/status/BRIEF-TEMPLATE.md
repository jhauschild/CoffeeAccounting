# Task agent brief (template)

You implement ONE task of the coffee-ledger v2 build in your own git worktree. Python: /home/claude/venv/bin/python; run pytest from your worktree root.

First command: `git reset --hard v2` (your worktree may start on an older commit; the tree is clean).
Read first: docs/V2-CONTRACT.md (authoritative), docs/status/TASKS.md (your row), the docs/status/task-*.md hand-offs of your dependencies, the source files you will change, and ONLY the sections of docs/PLAN-v2.md that the task names (docs/PLAN-v2-rev4.md lists amendments that win over PLAN-v2).
Rules: do only your task; services never commit; money is integer cents; typed errors from app/services/errors.py; strings via t(); no inline JS/CSS. Commit locally with a clear message when green; do NOT push; do NOT edit docs/status/TASKS.md, LOCK or BASELINE. Write a hand-off to docs/status/task-<id>.md (what changed, decisions, what later tasks must know, known-broken tests). Do not touch files owned by the task running concurrently with yours (the orchestrator names them).
Tests: add focused tests for your task; iterate with `pytest -q -x --tb=short <your files> | tail -40`; run the full suite ONCE at the end (`pytest -q --tb=line --ignore=tests/test_e2e_scan.py | tail -5`) and compare with docs/status/BASELINE (failed and errors must not increase; passed must grow).
Stop-loss: two failed fixes of the same failure => write the error to your hand-off, stop, and report `blocked`.
Final report under 150 words: what changed, test counts, what later tasks must know.

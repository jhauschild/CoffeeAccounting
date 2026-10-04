"""Final audit (task 7.2): scenario tests that drive the audit scripts in docs/status/repro/ as subprocesses.

* a long scripted scenario (200+ mixed operations through the services: registrations, scans, undo, price changes,
  payments by group admins and head admins, corrections, remittances, set_balance, merges, deactivations, role changes,
  chair changes) must end with `check-ledger` clean and every forbidden operation refused, and an INDEPENDENT raw-SQL
  recomputation (totals, group balances, chair roll-ups) must agree with the services, /admin/groups,
  /overview/chairs and the CSV exports;
* the authorization matrix: every route of the app (enumerated programmatically, 76 method/path pairs) probed as
  anonymous, signed-in member, group admin (own and foreign target) and head admin, with and without CSRF token and
  with a cross-site Origin; rejected requests change nothing, balance routes never book on the first request.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
REPRO = ROOT / "docs" / "status" / "repro"


def _env():
    env = {k: v for k, v in os.environ.items() if k not in ("DATABASE_URL", "ENVIRONMENT", "PUBLIC_BASE_URL", "SECRET_KEY")}
    env["PYTHONPATH"] = str(ROOT)
    return env


def _run(args, timeout=300):
    return subprocess.run([sys.executable, *map(str, args)], cwd=ROOT, env=_env(), capture_output=True, text=True,
                          timeout=timeout)


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_long_scenario_is_consistent_with_an_independent_recomputation(seed, tmp_path):
    db = tmp_path / f"scenario{seed}.db"
    run = _run([REPRO / "long_scenario.py", db, "--seed", seed, "--min-ops", 200])
    assert run.returncode == 0, run.stdout[-1500:] + run.stderr[-1500:]
    report = json.loads(run.stdout)
    assert report["ok_total"] >= 200
    assert report["unexpected"] == [] and report["must_refuse_but_succeeded"] == []
    assert report["check_ledger_ok"] is True and report["check_ledger_problems"] == []
    verify = _run([REPRO / "verify_scenario.py", db])
    assert verify.returncode == 0, verify.stdout[-2000:] + verify.stderr[-1000:]
    result = json.loads(verify.stdout[verify.stdout.index("{"):])
    assert result["failures"] == [] and result["checks"] >= 100


def test_authorization_matrix_over_every_route():
    run = _run([REPRO / "authz_matrix.py"], timeout=600)
    assert run.returncode == 0, run.stdout[-3000:] + run.stderr[-1000:]
    summary = json.loads(run.stdout[run.stdout.index("{"):])
    assert summary["failures"] == []
    assert summary["routes_without_policy"] == [] and summary["policy_entries_without_route"] == []
    assert summary["routes_enumerated"] >= 70 and summary["probes"] >= 700
    assert summary["positive_controls"]["ga renames in-scope"] == [303, True]
    assert summary["positive_controls"]["ga renames out-of-scope"][1] is False

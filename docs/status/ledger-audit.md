# ledger-audit status

## Done
- Read protocol, brief, ARCHITECTURE, PROMPT §3/§4/§12; baseline suite 444 passed.

## Next
- tests/test_audit_ledger_replay.py (HTTP replay/idempotency/pending/tamper)
- tests/test_audit_ledger_reversal.py (reversal races, adjustments)
- tests/test_audit_ledger_prices.py (snapshot edges, no recompute)
- tests/test_audit_ledger_merge.py (row hashes, chains, sessions)
- tests/test_audit_ledger_totals.py (credit, large, negative, SQL spot checks)
- tests/test_audit_ledger_checker.py (injected corruption)

## Notes/Blockers
- none

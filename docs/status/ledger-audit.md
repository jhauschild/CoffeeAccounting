# ledger-audit status

## Done
- tests/test_audit_ledger_replay.py: replay after registration/undo, cross-browser/pending replays, concurrent
  HTTP posts of one token, concurrent pending consumers, concurrent registration, deactivation before selection,
  token tampering (2 xfail: non-ASCII token/CSRF -> 500).
- tests/test_audit_ledger_reversal.py: undo vs admin reverse race, adjustment reversals (1 xfail: zero-amount
  adjustment cannot be reversed), reversal of reversal, admin route ownership, undo after rotation/merge/revocation.
- tests/test_audit_ledger_prices.py: effective_from boundary, price change GET->POST, future price, zero price,
  adjustment sign/size, AST "never recompute" check (1 xfail param x2: non-ASCII digits accepted).
- tests/test_audit_ledger_merge.py: row digests unchanged, chains re-pointed, opposite-merge race, inactive target,
  merge during in-flight scan, user table/dashboard vs raw SQL, correction across merge.
- tests/test_audit_ledger_totals.py: signed payments/corrections, concurrent corrections, large values, credit,
  per-chair netting after chair change.
- tests/test_audit_ledger_checker.py: 21 injected corruption kinds + CLI exit code (2 xfail gaps).
- Full suite: 516 passed, 7 xfailed.

## Next
- none (report delivered)

## Notes/Blockers
- Findings for owners A/B (no app code changed):
  - MED app/services/ledger.py:215-219 + models.py:213: zero-amount adjustment reversal -> CHECK violation mapped
    to AlreadyReversed.
  - LOW app/services/signing.py:66, app/web/tokens.py:71: non-ASCII str to hmac.compare_digest -> 500.
  - LOW app/money.py:11, app/web/admin_users.py:25: \d accepts non-ASCII digits.
  - LOW app/services/checker.py:131/147: no reversal chair check; no correction-owner check.

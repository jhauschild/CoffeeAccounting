# fixer-1 status

## Done
- Fix 1: zero-amount adjustment reversal (CHECK now allows type adjustment|reversal; initial migration edited in place;
  `_insert_once` re-raises non-unique IntegrityError; checker still flags zero-amount reversal of a non-zero-amount original).
- Fix 2: signature compare on bytes (signing.unsign, tokens.verify_csrf).
- Fix 3: ASCII-only digits in money.py, admin_users.py (and admin_auth TOTP regex).
- Fix 4: checker reports reversal_chair and correction_user (effective user, via merge chain).
- All six xfail markers removed; test_core_constraints updated for the relaxed CHECK.

## Next
- none

## Notes/Blockers
- A row-level CHECK cannot tell a reversal of a zero adjustment from a corrupt zero reversal; check-ledger covers it.

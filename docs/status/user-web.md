# user-web status

## Done
- app/web/routes_user.py, user_views.py, strings_user.py, templates/user/*, static/scan.js, static/user.css
- tests: test_user_scan.py, test_user_onboarding.py, test_user_account.py (+ tests/user_support.py); full suite green (276, incl. Playwright e2e using installed chromium-1194 via executable_path fallback)

## Next
- nothing (brief complete)

## Notes/Blockers
- /register and /profiles/select accept CSRF tokens bound to the user session OR the gate cookie (so a re-submitted registration form reaches the idempotent handler).
- A repeated registration submit (pending cookie already cleared) finds the first submit's coffee via created_at == user.created_at.

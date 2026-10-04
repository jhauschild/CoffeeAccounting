# Task 2.2: encrypted mail-login store, real SMTP backend, protocol and credential tests

Status: done. Commit "mail: encrypted credential store, verified-TLS SMTP backend, protocol tests (task 2.2)".
Full suite (e2e excluded): 1094 passed, 0 failed (baseline 1036); 58 new tests (24 credentials, 34 protocol), offline (127.0.0.1 only), run 3x without flakes.

## What changed
- `app/services/mail_credentials.py` (new). `save_credentials(username, password)` (InvalidInput for empty/absurd values, message never echoes the password), `load_credentials() -> MailCredentials(username, password)` (repr/str hide the password, not picklable), `clear_credentials() -> bool`, `status() -> MailLoginStatus(configured, masked_username, unreadable)` (`c***@lrz.de`; never the password), `mask_username`, `credentials_path()`.
  - File `SECRETS_DIR/mail-login.enc` = Fernet token (key `fernet_key("mail-credentials")`) of JSON. Directory created/fixed to 0700, file 0600 (`fchmod`, umask-safe), temp file in the same dir + fsync + `os.replace` + dir fsync; temp removed on any failure, old file kept.
  - Missing file: `MailError("not_configured")`. Wrong SECRET_KEY / corrupt / wrong content: `MailLoginUnreadable` (subclass of `MailError`, category `not_configured`), `str()` is exactly "mail login unreadable: re-run setup-mail", no cause chain. `status()` then reports `configured=False, unreadable=True` (CLI/admin page can show the message).
  - The module does not log.
- `app/services/mail.py`, smtp section only (plus `import time`): `SmtpMailer` is the real backend (`BACKENDS["smtp"]` unchanged slot). Settings `smtp_host/port/security`. `starttls`: requires the STARTTLS extension (else `tls`), upgrades, EHLO again; `ssl`: implicit TLS. AUTH only after `isinstance(client.sock, ssl.SSLSocket)`. Credentials loaded per send. Envelope sender = `sender_address()`, message from `to_email_message`. Timeouts `SMTP_CONNECT_TIMEOUT=10`, `SMTP_TOTAL_TIMEOUT=20` (module constants; per-step socket timeout = remaining time plus a watchdog that cuts the socket). Errors: only `MailError(category)` raised `from None`; categories connect/tls/auth/recipient_rejected/timeout/other via `_category_for` (looks through the exception chain, smtplib wraps socket timeouts; stage-aware: failure at STARTTLS is `tls`, DNS/OS error at connect is `connect`, AUTH not supported is `auth`). Status is NOT recorded by the backend.
  - `ssl_context_factory` (module-level, default `None`) is the injection point for tests; `default_ssl_context()` = `create_default_context()` + TLS 1.2 minimum. `_client_ssl_context()` refuses (MailError `tls`) any context whose `verify_mode != CERT_REQUIRED` or `check_hostname` is false, even an injected one: there is no code path to disable verification.
  - Debug output of smtplib is never enabled (it would print the AUTH data).
- `requirements-dev.txt`: `aiosmtpd==1.4.6` (installed in /home/claude/venv).
- Tests: `tests/test_platform_mail_credentials.py`, `tests/test_platform_smtp.py` (certificates generated per session with `cryptography`: test CA, unrelated CA, leaf with SAN localhost).

## Later tasks must know
- 4.5 CLI/admin: `from app.services import mail_credentials`; `setup-mail` = `save_credentials` (prompt with getpass), `mail-status` = `status()` + `mail.get_status()`, `clear-mail` = `clear_credentials()`, `test-mail` = `mail.get_mailer().send(mail.build_message(...))` then `mail.record_success/record_failure` yourself (the backend does not record; `mail._deliver` is private but records) or `send_mail`. Catch `MailError` and print `str(exc)` for the unreadable case (it is `mail login unreadable: re-run setup-mail`) and `exc.category` otherwise.
- Registration/recovery pages "temporarily unavailable": check `mail_credentials.status().configured`.
- aiosmtpd quirk (tests only): for implicit TLS the relay needs `auth_require_tls=False` because aiosmtpd does not count implicit TLS as TLS for AUTH; the test asserts the session really was TLS via the transport's `ssl_object`.
- Test env: with `MAIL_BACKEND=smtp` and no credentials, `test_smtp_backend_is_a_stub_until_task_2_2` in test_platform_mail.py still passes (not_configured) as long as `/secrets/mail-login.enc` does not exist on the machine; it should be renamed by whoever next touches that file.
- Known-broken tests: none.

"""First-setup and mail commands of `python -m app.cli` (owned by the admin agent; registered by `cli_admin`).

    setup-mail    ask for the SMTP login (hidden prompts) and store it encrypted under SECRETS_DIR
    mail-status   stored login (masked) and the last send result, readable across processes
    test-mail     send one real message through the configured backend
    clear-mail    delete the stored login
    setup         one guided run: head admin, TOTP hint, mail login, first price, optional test mail

Secrets: there is no `--password` option anywhere. The login is read with `getpass` (password twice) or, for
scripted installs, from stdin with `--password-stdin` (first line the username unless `--username` is given,
then the password). Abbreviations of options are off (`--password` is an error, not a shortcut for
`--password-stdin`). Output only ever contains the masked username and safe error categories.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import tempfile

from sqlalchemy.exc import SQLAlchemyError

from app.config import get_settings
from app.db import read_session, write_session
from app.money import format_money, parse_money
from app.services import admin_auth, audit, mail, mail_credentials, mail_status
from app.services.errors import InvalidInput, ServiceError
from app.services.prices import add_price, get_price_in_effect
from app.strings import t
from app.timeutil import format_local

TIME_FORMAT = "%Y-%m-%d %H:%M %Z"


def _err(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def _ask(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        raise SystemExit("error: input ended; run this command in an interactive terminal "
                         "(docker compose run --rm -it app ...)") from None


def _yes(prompt: str, default: bool = True) -> bool:
    answer = _ask(f"{prompt} {'[Y/n]' if default else '[y/N]'} ").strip().lower()
    return default if not answer else answer in ("y", "yes", "j", "ja")


def _audit(action: str, metadata: dict | None = None) -> None:
    """System-actor audit entry for a CLI action. The action has already happened, so a database that is not
    ready (not migrated yet) only produces a warning."""
    try:
        with write_session() as db:
            audit.log(db, actor_type="system", action=action, target_type="mail", metadata=metadata)
    except SQLAlchemyError:
        print("note: the action could not be written to the audit log (is the database migrated?)", file=sys.stderr)


# ----- secrets directory ------------------------------------------------------------------------------------------


def secrets_dir_problem() -> str | None:
    """None when the secrets directory can be used, else a clear message. A real probe (create and remove a file),
    so it is right for read-only mounts and wrong owners alike."""
    directory = mail_credentials.secrets_dir()
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=directory, prefix=".probe-")
        os.close(fd)
        os.unlink(name)
    except OSError:
        return (f"SECRETS_DIR ({directory}) is not writable by this user, so the mail login cannot be stored. "
                "Mount the secrets volume writable for the app user (see README) and run the command again.")
    return None


# ----- setup-mail ------------------------------------------------------------------------------------------------


def _read_login(args) -> tuple[str, str]:
    """Username and password from the prompts (password twice) or from stdin; never from argv."""
    username = (getattr(args, "username", None) or "").strip()
    if getattr(args, "password_stdin", False):
        if not username:
            username = sys.stdin.readline().rstrip("\r\n").strip()
        return username, sys.stdin.readline().rstrip("\r\n")
    if not username:
        username = getpass.getpass("SMTP username (input hidden): ").strip()
    password = getpass.getpass("SMTP password (input hidden): ")
    if getpass.getpass("Repeat the SMTP password: ") != password:
        raise InvalidInput("passwords do not match")
    return username, password


def cmd_setup_mail(args) -> int:
    problem = secrets_dir_problem()
    if problem:
        _err(problem)
        return 1
    try:
        username, password = _read_login(args)
        mail_credentials.save_credentials(username, password)
    except ServiceError as exc:
        _err(str(exc))
        return 1
    _audit("mail.login_saved")
    shown = mail_credentials.status()
    print(f"Mail login saved for {shown.masked_username or 'the given user'} (encrypted under SECRETS_DIR).")
    backend = get_settings().mail_backend
    if backend != "smtp":
        print(f"Note: MAIL_BACKEND is {backend!r}; the login is only used by the smtp backend.")
    print("Check it with: python -m app.cli test-mail you@example.org")
    return 0


# ----- mail-status -----------------------------------------------------------------------------------------------


def _when(moment) -> str:
    return format_local(moment, TIME_FORMAT) if moment else "never"


def cmd_mail_status(args) -> int:
    try:
        with read_session() as db:
            card = mail_status.card(db)
        persisted = True
    except SQLAlchemyError:  # database missing or not migrated: still report the login
        login = mail_credentials.status()
        card = mail_status.MailCard(
            backend=get_settings().mail_backend or "smtp", configured=login.configured,
            masked_username=login.masked_username, unreadable=login.unreadable,
            needs_login=get_settings().mail_backend == "smtp", last_ok_at=None, last_failure_category=None,
            last_failure_at=None, cap_reached=False, max_per_hour=get_settings().mail_max_per_hour, banner=None)
        persisted = False
    if card.unreadable:
        print(f"mail configured: no ({mail_credentials.UNREADABLE_MESSAGE})")
    elif card.configured:
        print(f"mail configured: yes, user {card.masked_username}")
    else:
        print("mail configured: no (run setup-mail)")
    settings = get_settings()
    print(f"backend: {card.backend}" + (f" ({settings.smtp_host}:{settings.smtp_port}, {settings.smtp_security})"
                                         if card.backend == "smtp" else " (development backend, no login needed)"))
    if not persisted:
        print("last send: unknown (database not available)")
        return 0
    print(f"last send OK: {_when(card.last_ok_at)}")
    if card.last_failure_category:
        print(f"last failure: {card.last_failure_category} at {_when(card.last_failure_at)}")
    else:
        print("last failure: none")
    if card.banner == mail_status.BANNER_CAP_REACHED:
        print(f"state: cap reached ({card.max_per_hour} mails per hour blocked sending; nothing is broken)")
    elif card.banner == mail_status.BANNER_FAILING:
        print(f"state: mail failing: {card.last_failure_category}")
    elif card.banner == mail_status.BANNER_NOT_CONFIGURED:
        print("state: mail not configured")
    else:
        print("state: ok" if card.last_ok_at else "state: no mail sent yet")
    return 0


# ----- test-mail -------------------------------------------------------------------------------------------------


def send_test_mail(address: str) -> int:
    """One real message through the configured backend, via the path that records the status."""
    try:
        message = mail.build_message(to=address, subject=t("admin.mail.test_subject"), body=t("admin.mail.test_body"))
    except ServiceError:
        _err("not a valid e-mail address")
        return 2
    if get_settings().mail_backend == "smtp":
        login = mail_credentials.status()
        if login.unreadable:
            _err(mail_credentials.UNREADABLE_MESSAGE)
            return 1
        if not login.configured:
            _err("mail login not configured: run setup-mail first")
            return 1
    category = mail.send_in_background(message, address)
    if category is None:
        print(f"Test mail sent to {message.to}.")
        return 0
    hint = t(f"admin.mail.hint.{category}")
    _err(f"test mail failed: {category}. {hint}")
    return 1


def cmd_test_mail(args) -> int:
    return send_test_mail(args.address)


# ----- clear-mail ------------------------------------------------------------------------------------------------


def cmd_clear_mail(args) -> int:
    if not args.yes and not _yes("Delete the stored mail login? Registration and password reset stop working until "
                                 "setup-mail is run again.", default=False):
        print("Nothing changed.")
        return 0
    try:
        removed = mail_credentials.clear_credentials()
    except ServiceError as exc:
        _err(str(exc))
        return 1
    if removed:
        _audit("mail.login_cleared")
        print("Stored mail login deleted.")
    else:
        print("No mail login was stored.")
    return 0


# ----- setup (guided) --------------------------------------------------------------------------------------------


def _step_admin() -> bool:
    from app.cli_admin import cmd_create_admin

    with read_session() as db:
        existing = [a.username for a in admin_auth.list_admins(db) if a.role == "global"]
    if existing:
        print(f"A head administrator already exists ({', '.join(existing)}).")
    if not _yes("Create a head administrator now?", default=not existing):
        return True
    username = _ask("Username: ").strip()
    ns = argparse.Namespace(username=username, role="global", password_stdin=False)
    return cmd_create_admin(ns) == 0


def _step_totp() -> bool:
    base = get_settings().public_base_url
    print("Two-factor authentication is enrolled once, at the first login: open "
          f"{base}/admin/login, sign in with the password, and the page shows a QR code for an authenticator app "
          "and 8 recovery codes. Enrol right after creating the account.")
    return True


def _step_mail() -> bool:
    status = mail_credentials.status()
    if status.configured:
        print(f"A mail login is already stored ({status.masked_username}).")
    if not _yes("Store the mail login now?", default=not status.configured):
        return True
    return cmd_setup_mail(argparse.Namespace(username=None, password_stdin=False)) == 0


def _step_price() -> bool:
    with read_session() as db:
        current = get_price_in_effect(db)
        current_text = format_money(current.price_per_shot_cents) if current else None
    if current_text:
        print(f"A price is already in effect: {current_text} per shot.")
    if not _yes("Set the price per shot now?", default=current_text is None):
        return True
    try:
        cents = parse_money(_ask("Price per shot, e.g. 0.50: "), allow_negative=False, allow_zero=True)
        with write_session() as db:
            price = add_price(db, price_per_shot_cents=cents, effective_from=None, admin_id=None, note=None)
            shown = format_money(price.price_per_shot_cents)
    except (ServiceError, ValueError) as exc:
        _err(str(exc))
        return False
    print(f"Price set: {shown} per shot, effective now.")
    return True


def _step_test_mail() -> bool:
    if not _yes("Send a test mail now?", default=False):
        return True
    address = _ask("Send to (address): ").strip()
    return send_test_mail(address) == 0


def cmd_setup(args) -> int:
    print("Guided setup. Each step can be skipped, and each also exists as its own command "
          "(create-admin, setup-mail, set-price, test-mail).")
    steps = (("1. Head administrator", _step_admin), ("2. Two-factor authentication", _step_totp),
             ("3. Mail login", _step_mail), ("4. First price", _step_price), ("5. Test mail", _step_test_mail))
    failed = []
    for title, step in steps:
        print(f"\n{title}")
        try:
            if not step():
                failed.append(title)
        except (SQLAlchemyError, OSError) as exc:
            _err(f"{type(exc).__name__}: is the database migrated (alembic upgrade head)?")
            failed.append(title)
    print()
    if failed:
        print("Not completed: " + "; ".join(failed) + ". Run the step's own command to retry.")
        return 1
    print("Setup finished.")
    return 0


# ----- registration ----------------------------------------------------------------------------------------------


def register(subparsers) -> None:
    p = subparsers.add_parser("setup-mail", allow_abbrev=False, help="store the SMTP login (hidden prompts; encrypted under SECRETS_DIR)")
    p.add_argument("--username", help="SMTP username (optional; otherwise prompted)")
    p.add_argument("--password-stdin", action="store_true",
                   help="scripted installs: read the password from stdin (first the username line unless --username)")
    p.set_defaults(func=cmd_setup_mail)

    p = subparsers.add_parser("mail-status", help="stored login (masked) and the last send result")
    p.set_defaults(func=cmd_mail_status)

    p = subparsers.add_parser("test-mail", help="send one real test message through the configured mail backend")
    p.add_argument("address", metavar="ADDRESS")
    p.set_defaults(func=cmd_test_mail)

    p = subparsers.add_parser("clear-mail", help="delete the stored mail login")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    p.set_defaults(func=cmd_clear_mail)

    p = subparsers.add_parser("setup", help="guided first setup: head admin, mail login, first price, test mail")
    p.set_defaults(func=cmd_setup)

"""Admin CLI commands (owned by the admin agent): `python -m app.cli <command>`.

Contract: `register(subparsers)` adds sub-commands to the `python -m app.cli` parser.
Each sub-parser sets `func(args) -> int` (the process exit code). Passwords are never taken
from the command line: they are prompted for (twice), or read from stdin with `--password-stdin`.
All management actions are audited with the `system` actor.
"""

from __future__ import annotations

import getpass
import sys

from app.db import read_session, write_session
from app.services import admin_auth, exports
from app.services.errors import InvalidInput, ServiceError


def _fail(message: str, code: int = 1) -> int:
    print(f"error: {message}", file=sys.stderr)
    return code


def _read_password(args, prompt: str = "Password: ") -> str:
    if getattr(args, "password_stdin", False):
        return sys.stdin.readline().rstrip("\r\n")
    first = getpass.getpass(prompt)
    if getpass.getpass("Repeat password: ") != first:
        raise InvalidInput("passwords do not match")
    return first


def cmd_create_admin(args) -> int:
    try:
        password = _read_password(args)
        with write_session() as db:
            admin = admin_auth.create_admin(db, username=args.username, password=password, role=args.role)
            name, role = admin.username, admin.role
    except ServiceError as exc:
        return _fail(str(exc))
    print(f"Administrator {name!r} ({role}) created. TOTP is enrolled once at the first login.")
    return 0


def cmd_reset_admin_password(args) -> int:
    try:
        password = _read_password(args, "New password: ")
        with write_session() as db:
            admin_auth.reset_password(db, admin_auth.get_admin(db, args.username), password)
    except ServiceError as exc:
        return _fail(str(exc))
    print(f"Password of {args.username!r} reset; all of their sessions were revoked.")
    return 0


def cmd_reset_admin_totp(args) -> int:
    try:
        with write_session() as db:
            admin_auth.reset_totp(db, admin_auth.get_admin(db, args.username))
    except ServiceError as exc:
        return _fail(str(exc))
    print(f"TOTP of {args.username!r} reset; they enrol again (forced while BALANCE_TOTP_REQUIRED).")
    return 0


def cmd_disable_admin(args) -> int:
    try:
        with write_session() as db:
            admin_auth.set_admin_active(db, admin_auth.get_admin(db, args.username), bool(args.enable))
    except ServiceError as exc:
        return _fail(str(exc))
    print(f"Administrator {args.username!r} {'enabled' if args.enable else 'disabled'}.")
    return 0


def cmd_list_admins(args) -> int:
    with read_session() as db:
        for admin in admin_auth.list_admins(db):
            chairs = ",".join(sorted(c.short_name for c in admin.chairs)) or "-"
            print(f"{admin.username}\t{admin.role}\tchairs={chairs}\t"
                  f"{'active' if admin.active else 'disabled'}\ttotp={'on' if admin.totp_enabled else 'off'}")
    return 0


def cmd_bootstrap_admin(args) -> int:
    try:
        with write_session() as db:
            admin = admin_auth.bootstrap_admin(db)
            name = admin.username if admin else None
    except ServiceError as exc:
        return _fail(str(exc))
    if name:
        print(f"Administrator {name!r} (global) created from ADMIN_BOOTSTRAP_*.")
    else:
        print("Nothing to do (ADMIN_BOOTSTRAP_* not set, or an administrator already exists).")
    return 0


def cmd_qr(args) -> int:
    names = exports.write_qr_files(args.out)
    print(f"Wrote {', '.join(names)} to {args.out}")
    for kind, url in exports.qr_urls().items():
        print(f"  {kind}: {url}")
    return 0


def register(subparsers) -> None:
    p = subparsers.add_parser("create-admin", help="create an administrator (prompts for the password)")
    p.add_argument("--username", required=True)
    p.add_argument("--role", required=True, choices=["global", "chair"])
    p.add_argument("--password-stdin", action="store_true", help="read the password from stdin instead of prompting")
    p.set_defaults(func=cmd_create_admin)

    p = subparsers.add_parser("reset-admin-password", help="set a new password and revoke the admin's sessions")
    p.add_argument("--username", required=True)
    p.add_argument("--password-stdin", action="store_true")
    p.set_defaults(func=cmd_reset_admin_password)

    p = subparsers.add_parser("reset-admin-totp", help="forget TOTP secret and recovery codes (enrol again; forced while BALANCE_TOTP_REQUIRED)")
    p.add_argument("--username", required=True)
    p.set_defaults(func=cmd_reset_admin_totp)

    p = subparsers.add_parser("disable-admin", help="disable an administrator and revoke their sessions")
    p.add_argument("--username", required=True)
    p.add_argument("--enable", action="store_true", help="re-enable instead of disabling")
    p.set_defaults(func=cmd_disable_admin)

    p = subparsers.add_parser("list-admins", help="list administrators")
    p.set_defaults(func=cmd_list_admins)

    p = subparsers.add_parser("bootstrap-admin", help="create the first admin from ADMIN_BOOTSTRAP_* (if none exists)")
    p.set_defaults(func=cmd_bootstrap_admin)

    p = subparsers.add_parser("qr", help="write printable SVG QR codes for the two scan URLs")
    p.add_argument("--out", required=True, metavar="DIR")
    p.set_defaults(func=cmd_qr)

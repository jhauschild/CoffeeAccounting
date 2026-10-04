"""Command line interface: `python -m app.cli <command>`.

Commands here: check-ledger, set-price, purge-expired. Admin management commands are
registered by `app.cli_admin.register(subparsers)` (each sub-parser sets `func(args) -> int`).
"""

from __future__ import annotations

import argparse
import importlib
import sys
from datetime import timedelta

from sqlalchemy import delete, or_

from app.db import read_session, write_session
from app.models import (AdminSession, PasswordResetToken, PendingAction, PendingRegistration, RateLimitEvent,
                        UserSession)
from app.money import format_money
from app.services import audit
from app.services.checker import check_ledger
from app.services.errors import ServiceError
from app.services.prices import add_price
from app.timeutil import format_local, parse_iso_datetime, utcnow

REVOKED_SESSION_RETENTION = timedelta(days=30)
RATE_LIMIT_RETENTION = timedelta(days=1)


def cmd_check_ledger(args) -> int:
    with read_session() as db:
        report = check_ledger(db)
    for p in report.problems:
        print(f"PROBLEM [{p.code}] {p.message}")
    summary = (f"{report.consumption_events} consumption events, {report.payment_events} payment events, "
               f"{report.users} users, {report.prices} prices checked")
    if report.ok:
        print(f"OK: {summary}")
    else:
        print(f"FAILED: {len(report.problems)} problem(s); {summary}", file=sys.stderr)
    for note in report.notes:
        print(f"NOTE {note}")
    return 0 if report.ok else 1


def cmd_set_price(args) -> int:
    try:
        effective_from = parse_iso_datetime(args.effective_from) if args.effective_from else None
    except ValueError:
        print("error: --from must be an ISO 8601 date/time", file=sys.stderr)
        return 2
    try:
        with write_session() as db:
            price = add_price(db, price_per_shot_cents=args.cents, effective_from=effective_from, admin_id=None,
                              note=args.note)
            shown = (format_money(price.price_per_shot_cents), format_local(price.effective_from, "%Y-%m-%d %H:%M %Z"))
    except ServiceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Price set: {shown[0]} per shot, effective from {shown[1]}")
    return 0


def cmd_purge_expired(args) -> int:
    now = utcnow()
    with write_session() as db:
        counts = {}
        for name, model in (("user_sessions", UserSession), ("admin_sessions", AdminSession)):
            counts[name] = db.execute(
                delete(model).where(or_(model.expires_at < now, model.revoked_at < now - REVOKED_SESSION_RETENTION))
            ).rowcount
        counts["pending_actions"] = db.execute(delete(PendingAction).where(PendingAction.expires_at < now)).rowcount
        # Registration and reset links: expired ones are useless, consumed ones have done their job.
        for name, model in (("pending_registrations", PendingRegistration), ("reset_links", PasswordResetToken)):
            counts[name] = db.execute(
                delete(model).where(or_(model.expires_at < now, model.consumed_at.is_not(None)))).rowcount
        counts["rate_limit_events"] = db.execute(
            delete(RateLimitEvent).where(RateLimitEvent.created_at < now - RATE_LIMIT_RETENTION)
        ).rowcount
        audit.log(db, actor_type="system", action="maintenance.purge_expired", metadata=counts, now=now)
    print("Purged: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="Coffee ledger administration")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("check-ledger", help="verify ledger invariants; exits non-zero on problems")
    p.set_defaults(func=cmd_check_ledger)

    p = sub.add_parser("set-price", help="add a new price per shot (cannot be backdated)")
    p.add_argument("--cents", type=int, required=True, help="price per shot in cents, e.g. 50")
    p.add_argument("--from", dest="effective_from", help="ISO 8601 start (default now; no offset = local time)")
    p.add_argument("--note", help="optional note")
    p.set_defaults(func=cmd_set_price)

    p = sub.add_parser("purge-expired", help="delete expired sessions, pending actions, expired or used registration and reset links, old rate-limit rows")
    p.set_defaults(func=cmd_purge_expired)

    try:
        cli_admin = importlib.import_module("app.cli_admin")
    except ModuleNotFoundError as exc:
        if exc.name != "app.cli_admin":
            raise
    else:
        cli_admin.register(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())

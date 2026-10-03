"""ledger-audit: price snapshot edges, adjustment amounts, and "never recompute" checks."""

from __future__ import annotations

import ast
from datetime import timedelta
from pathlib import Path

import pytest

from app.db import write_session
from app.models import AdminUser
from app.money import parse_money
from app.services import ledger, prices
from app.services.checker import check_ledger
from app.services.errors import InvalidAmount
from app.timeutil import utcnow
from tests import factories
from tests.user_support import event_id_from, events, post_scan, scan_token

ROOT = Path(__file__).resolve().parent.parent


def test_event_exactly_at_effective_from_uses_the_new_price(db, user, global_admin):
    t0 = utcnow() - timedelta(hours=2)
    old = factories.set_price(db, 40, effective_from=t0)
    t1 = t0 + timedelta(hours=1)
    new = factories.set_price(db, 65, effective_from=t1)
    before = ledger.record_coffee(db, user_id=user.id, kind="single", nonce="before", now=t1 - timedelta(microseconds=1))
    at = ledger.record_coffee(db, user_id=user.id, kind="double", nonce="at", now=t1)
    assert (before.event.price_id, before.event.amount_cents) == (old.id, 40)
    assert (at.event.price_id, at.event.amount_cents) == (new.id, 130)
    db.commit()
    assert check_ledger(db).ok, check_ledger(db).problems


def test_price_change_between_get_and_post_uses_price_at_insert(client, db, user, price, login, global_admin):
    login(user)
    token = scan_token(client, "double")  # page rendered at 50/shot
    with write_session() as w:
        prices.add_price(w, price_per_shot_cents=80, admin_id=global_admin.id)
    event_id_from(post_scan(client, "double", token))
    (event,) = events(db)
    assert (event.unit_price_cents, event.amount_cents) == (80, 160)


def test_future_price_added_after_scan_page_does_not_apply_early(client, db, user, price, login, global_admin):
    login(user)
    with write_session() as w:
        prices.add_price(w, price_per_shot_cents=99, effective_from=utcnow() + timedelta(minutes=5),
                         admin_id=global_admin.id)
    event_id_from(post_scan(client, "single"))
    (event,) = events(db)
    assert (event.price_id, event.amount_cents) == (price.id, 50)


def test_zero_price_coffee_and_its_undo_are_consistent(db, user, global_admin):
    factories.set_price(db, 0)
    session = factories.make_session(db, user)
    (event,) = factories.add_events(db, user, "double", session_id=session.id)
    rev = ledger.undo_coffee(db, user_id=user.id, session_id=session.id, event_id=event.id)
    assert (event.amount_cents, rev.quantity, rev.amount_cents) == (0, -2, 0)
    db.commit()
    assert check_ledger(db).ok


# ----- adjustments -------------------------------------------------------------------------------
@pytest.mark.parametrize("quantity,amount", [(-2, 100), (2, -1), (0, 0), (1001, None), (1, 10 ** 12), (True, 5),
                                             (1, 1.5)])
def test_adjustment_rejects_bad_sign_or_size(db, user, price, global_admin, quantity, amount):
    with pytest.raises(InvalidAmount):
        ledger.add_adjustment(db, admin=global_admin, user_id=user.id, quantity=quantity, amount_cents=amount)


def test_adjustment_amount_is_stored_verbatim_and_never_recomputed(db, user, price, global_admin):
    adj = ledger.add_adjustment(db, admin=global_admin, user_id=user.id, quantity=-3, amount_cents=-149)
    db.commit()
    factories.set_price(db, 500, effective_from=utcnow())
    db.expire_all()
    assert ledger.get_totals(db, user.id).consumed_amount_cents == -149
    assert (adj.unit_price_cents, adj.price_id) == (50, price.id)


def test_adjustment_route_rejects_non_integer_quantity(app, db, user, price):
    from tests.admin_support import login_as, make_real_admin, new_client

    admin_id, _ = make_real_admin(username="boss")
    c = new_client(app)
    csrf = login_as(c, admin_id)
    for qty in ("1.5", "2e1", "", "--1", "99999"):
        c.post(f"/admin/users/{user.id}/adjustment", data={"csrf_token": csrf, "quantity": qty, "amount": ""},
               follow_redirects=False)
    assert events(db) == []
    c.post(f"/admin/users/{user.id}/adjustment", data={"csrf_token": csrf, "quantity": "2", "amount": ""},
           follow_redirects=False)  # positive control: the session and form work
    assert [(e.type, e.quantity, e.amount_cents) for e in events(db)] == [("adjustment", 2, 100)]


@pytest.mark.xfail(strict=True, reason="BUG(low): money/int regexes use \\d, which accepts non-ASCII digits "
                                       "(e.g. Arabic-Indic, full-width); PROMPT §6 asks for strict parsing")
@pytest.mark.parametrize("text", ["١٢,٥٠", "１２.５０"])
def test_parse_money_rejects_non_ascii_digits(text):
    with pytest.raises(InvalidAmount):
        parse_money(text)


# ----- no recomputation with the current price ---------------------------------------------------
ALLOWED_PRICE_MULTIPLICATIONS = {
    ("app/services/ledger.py", "record_coffee"),          # snapshot at insert time
    ("app/services/ledger.py", "adjustment_default_amount"),  # form pre-fill only
    ("app/services/ledger.py", "add_adjustment"),         # default amount at insert time
}


def _price_multiplications():
    found = set()
    for path in (ROOT / "app").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for func in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            for node in ast.walk(func):
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
                    text = ast.unparse(node)
                    if "price" in text and "quantity" in text:
                        found.add((path.relative_to(ROOT).as_posix(), func.name))
    return found


def test_amounts_are_never_recomputed_from_the_current_price():
    found = _price_multiplications()
    assert ("app/services/ledger.py", "record_coffee") in found  # the scan itself works
    unexpected = found - ALLOWED_PRICE_MULTIPLICATIONS
    # checker.py multiplies the *stored* unit price (verification, not recomputation).
    unexpected.discard(("app/services/checker.py", "check_ledger"))
    assert not unexpected, unexpected
    templates = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "templates").rglob("*.html"))
    assert "quantity *" not in templates and "* price" not in templates


def test_totals_ignore_price_changes(db, user, price, global_admin):
    factories.add_events(db, user, ["single", "double"])
    before = ledger.get_totals(db, user.id)
    for cents in (10, 0, 9999):
        with write_session() as w:
            prices.add_price(w, price_per_shot_cents=cents, admin_id=w.get(AdminUser, global_admin.id).id)
    db.expire_all()
    assert ledger.get_totals(db, user.id) == before == ledger.Totals(3, 150, 0, 150)

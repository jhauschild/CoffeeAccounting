"""Final audit (task 7.2) reproduction: reversing a NEGATIVE adjustment crashes with an unhandled IntegrityError.

    python docs/status/repro/repro_reverse_negative_adjustment.py

A head admin books an adjustment of -2 shots (a correction in the customer's favour). Reversing that event
(`ledger.admin_reverse_event`) inserts a reversal row whose quantity is the NEGATION of the original (+2); the
table check `ck_consumption_events_reversal_shape` only allows reversal rows with quantity < 0, so SQLite
raises IntegrityError, which is not a ServiceError. Over HTTP the step-up confirm POST then answers 500.

Prints what happened at service level and over HTTP; exit code 1 when the defect reproduces (so a fixed
build exits 0).
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
tmp = tempfile.mkdtemp(prefix="repro-negadj-")
DB = os.path.join(tmp, "r.db")
os.environ.update(ENVIRONMENT="development", PUBLIC_BASE_URL="http://testserver", MAIL_BACKEND="memory",
                  SECRET_KEY="audit-repro-secret-0123456789abcdef-xyz", DATABASE_URL=f"sqlite:///{DB}",
                  ARGON2_TIME_COST="1", ARGON2_MEMORY_COST_KIB="8", ARGON2_PARALLELISM="1", TRUSTED_PROXY_IPS="",
                  BALANCE_TOTP_REQUIRED="false")

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402

cfg = Config(str(ROOT / "alembic.ini"))
cfg.attributes["url"] = f"sqlite:///{DB}"
cfg.attributes["configure_logger"] = False
command.upgrade(cfg, "head")

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.db import read_session, write_session  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import ConsumptionEvent, AdminUser  # noqa: E402
from app.services import admin_auth, ledger  # noqa: E402
from app.timeutil import utcnow  # noqa: E402
from app.web import tokens  # noqa: E402
from tests import factories  # noqa: E402

with write_session() as w:
    chair = factories.make_chair(w, commit=False)
    factories.set_price(w, 50, commit=False)
    head = factories.make_admin(w, "global", username="head", commit=False)
    admin_auth.begin_enrollment(w, head)
    head.totp_enabled = True
    user = factories.make_member(w, "Alice", chair, commit=False)
    w.flush()
    adj = ledger.add_adjustment(w, admin=head, user_id=user.id, quantity=-2, note="goodwill")
    adj_id, uid, head_id = adj.id, user.id, head.id
print("adjustment event:", adj_id, "quantity -2")

# 1. service level
outcome = "no error"
try:
    with write_session() as w:
        admin = w.get(AdminUser, head_id)
        ledger.admin_reverse_event(w, admin=admin, event_id=adj_id, note="undo")
except Exception as exc:  # noqa: BLE001
    outcome = f"{type(exc).__module__}.{type(exc).__name__}: {str(exc).splitlines()[0][:120]}"
print("service level:", outcome)

# 2. HTTP level: preview then confirm
app = create_app()
c = TestClient(app, raise_server_exceptions=False, follow_redirects=False)
with write_session() as w:
    admin = w.get(AdminUser, head_id)
    session, raw = admin_auth._new_session(w, admin, now=utcnow())
    csrf = tokens.csrf_token("admin", session.csrf_secret)
c.cookies.set("coffee_admin", raw, path="/admin")
page = c.get(f"/admin/users/{uid}")
shows_button = f"/events/{adj_id}/reverse" in page.text
print("detail page offers the reverse button for the -2 adjustment:", shows_button)
r = c.post(f"/admin/users/{uid}/events/{adj_id}/reverse", data={"csrf_token": csrf, "note": "undo"},
           headers={"Origin": "http://testserver"})
print("preview POST:", r.status_code, "|", re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", r.text))[:120])
print("traceback or class name leaked in preview body:", "Traceback" in r.text or "IntegrityError" in r.text)
http_status = r.status_code if r.status_code >= 500 else None
if r.status_code == 200:
    fields = {n: re.search(rf'name="{n}" value="([^"]*)"', r.text).group(1) for n in ("csrf_token", "payload", "nonce")}
    r2 = c.post("/admin/stepup/confirm", data=fields, headers={"Origin": "http://testserver"})
    http_status = r2.status_code
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", r2.text))[:140]
    print("confirm POST:", r2.status_code, "|", text)
    print("traceback or class name leaked in body:", "Traceback" in r2.text or "IntegrityError" in r2.text)
with read_session() as db:
    n = len(db.scalars(select(ConsumptionEvent)).all())
print("events in ledger afterwards:", n, "(unchanged: nothing was booked, nothing corrupted)")
reproduced = outcome.endswith("IntegrityError") or "IntegrityError" in outcome or http_status == 500
print("DEFECT REPRODUCED" if reproduced else "not reproduced")
sys.exit(1 if reproduced else 0)

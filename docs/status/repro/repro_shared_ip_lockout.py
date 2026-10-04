"""Final audit (task 7.2) reproduction: with the shipped default TRUSTED_PROXY_IPS (empty), every visitor behind the
reverse proxy shares ONE client address, so 20 failed sign-ins by anyone lock the password sign-in out for everyone.

    python docs/status/repro/repro_shared_ip_lockout.py

docker-compose.yml publishes the app on 127.0.0.1 and the container sees the Docker bridge gateway as the peer, not the
visitor. The app only believes X-Forwarded-For from TRUSTED_PROXY_IPS (empty by default; README "Trusted proxy
addresses" says to set it, nothing enforces or warns). This script plays that deployment: all requests come from
the same TCP peer (as behind the proxy), the proxy puts the visitor in X-Forwarded-For (ignored: not trusted).
An attacker sends 20 sign-ins with unknown usernames; the victim then signs in with the CORRECT password and is
answered 429. Prints the status codes; exit code 1 when the lock-out reproduces.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
tmp = tempfile.mkdtemp(prefix="repro-ip-")
DB = os.path.join(tmp, "r.db")
os.environ.update(ENVIRONMENT="development", PUBLIC_BASE_URL="http://testserver", MAIL_BACKEND="memory",
                  SECRET_KEY="audit-repro-secret-0123456789abcdef-xyz", DATABASE_URL=f"sqlite:///{DB}",
                  ARGON2_TIME_COST="1", ARGON2_MEMORY_COST_KIB="8", ARGON2_PARALLELISM="1", TRUSTED_PROXY_IPS="")

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402

cfg = Config(str(ROOT / "alembic.ini"))
cfg.attributes["url"] = f"sqlite:///{DB}"
cfg.attributes["configure_logger"] = False
command.upgrade(cfg, "head")

from fastapi.testclient import TestClient  # noqa: E402

from app.db import write_session  # noqa: E402
from app.main import create_app  # noqa: E402
from app.services.passwords import hash_password  # noqa: E402
from tests import factories  # noqa: E402

with write_session() as w:
    chair = factories.make_chair(w, commit=False)
    factories.make_member(w, "Victim", chair, username="victim", password_hash=hash_password("correct horse battery"), commit=False)
app = create_app()


def post_login(xff, username, password):
    c = TestClient(app, raise_server_exceptions=False, follow_redirects=False)
    page = c.get("/login", headers={"X-Forwarded-For": xff})
    tok = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    return c.post("/login", data={"csrf_token": tok, "username": username, "password": password},
                  headers={"X-Forwarded-For": xff, "Origin": "http://testserver"}).status_code


codes = [post_login("203.0.113.9", f"nouser{i}", "wrong") for i in range(1, 22)]
print("attacker (X-Forwarded-For 203.0.113.9), 21 sign-ins with unknown usernames:", codes)
victim = post_login("198.51.100.7", "victim", "correct horse battery")
print("victim (other visitor, X-Forwarded-For 198.51.100.7) signs in with the CORRECT password:", victim)
print("LOCKOUT REPRODUCED" if victim == 429 else "not reproduced")
sys.exit(1 if victim == 429 else 0)

"""Admin pages over HTTP: dashboard, user table, CSV downloads, QR page, template hygiene."""

from __future__ import annotations

import csv
import glob
import io
import re
from pathlib import Path

import pytest
from sqlalchemy import select

from app.db import read_session
from app.models import AuditLog
from app.strings import CATALOGS
from tests import factories
from tests.admin_support import fast_hasher, login_as, make_real_admin, new_client  # noqa: F401

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def gc(app):
    admin_id, _ = make_real_admin(username="boss")
    c = new_client(app)
    return c, login_as(c, admin_id)


@pytest.fixture
def cc(app, chair):
    admin_id, _ = make_real_admin(role="chair", chairs=[chair], username="chairadmin")
    c = new_client(app)
    return c, login_as(c, admin_id)


def rows_of(response):
    assert response.content.startswith(b"\xef\xbb\xbf")
    return list(csv.reader(io.StringIO(response.content.decode("utf-8-sig")), delimiter=";"))


def test_dashboard_page_numbers(gc, db, chair, other_chair, price):
    a = factories.make_user(db, "Alice", chair)
    b = factories.make_user(db, "Bob", other_chair)
    admin = factories.make_admin(db, "global")
    factories.add_events(db, a, ["single", "double"])   # 3 shots, 150 cents
    factories.add_events(db, b, ["single"])             # 1 shot, 50 cents
    factories.make_payment(db, a, admin, 100)
    page = gc[0].get("/admin").text
    totals = re.search(r'<dl class="totals">(.*?)</dl>', page, re.S).group(1)
    cells = [re.sub(r"<[^>]+>", "", c).strip() for c in re.findall(r"<d[td][^>]*>(.*?)</d[td]>", totals, re.S)]
    assert cells == ["Shots", "4", "Consumed", "€2.00", "Paid", "€1.00", "Balance", "€1.00"]
    assert "Today" in page and "This week" in page and "This month" in page
    assert "€0.50" in page  # current price
    for name in ("Alice", "Bob"):
        assert name in page  # latest consumption


def test_dashboard_without_price_warns(gc):
    assert "No price is configured" in gc[0].get("/admin").text


def test_chair_admin_dashboard_is_scoped(cc, db, chair, other_chair, price):
    factories.add_events(db, factories.make_user(db, "Mine", chair), "single")
    factories.add_events(db, factories.make_user(db, "Theirs", other_chair), "double")
    page = cc[0].get("/admin").text
    assert "Mine" in page and "Theirs" not in page
    assert other_chair.short_name not in page.split("By ")[1].split("</section>")[0]


def test_user_table_search_sort_filter_pagination(gc, db, chair, other_chair, price):
    for i in range(55):
        factories.make_user(db, f"User {i:02d}", chair)
    factories.make_user(db, "Müller", other_chair)
    c = gc[0]
    assert "Müller" in c.get("/admin/users?q=muller").text and "User 01" not in c.get("/admin/users?q=muller").text
    assert "Müller" in c.get("/admin/users?q=mueller").text
    first = c.get("/admin/users?sort=name").text
    second = c.get("/admin/users?sort=name&page=2").text
    assert "User 00" in first and "User 54" not in first and "User 54" in second and "Page 1 of 2" in first
    assert "Müller" not in c.get(f"/admin/users?chair={chair.id}&sort=name&page=2").text
    assert "Müller" in c.get(f"/admin/users?chair={other_chair.id}").text
    assert "User 00" not in c.get(f"/admin/users?chair={other_chair.id}").text
    assert c.get("/admin/users?chair=garbage", follow_redirects=False).status_code == 404
    assert c.get("/admin/users?page=0").status_code == 400
    assert c.get("/admin/users?sort=drop table").status_code == 200  # unknown sort falls back, never errors


def test_users_csv_route_honors_filters_and_is_audited(gc, cc, db, chair, other_chair, price):
    factories.make_user(db, "=cmd|' /C calc'!A0", chair)
    factories.make_user(db, "Plain", chair)
    factories.make_user(db, "Elsewhere", other_chair)
    r = gc[0].get(f"/admin/users/export.csv?chair={chair.id}&sort=name")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert 'attachment; filename="coffee-users-' in r.headers["content-disposition"]
    names = [row[0] for row in rows_of(r)[1:]]
    assert names == ["'=cmd|' /C calc'!A0", "Plain"]  # filtered by chair, formula neutralized
    r = gc[0].get("/admin/users/export.csv?q=elsew")
    assert [row[0] for row in rows_of(r)[1:]] == ["Elsewhere"]
    assert [row[0] for row in rows_of(cc[0].get("/admin/users/export.csv"))[1:]] == ["'=cmd|' /C calc'!A0", "Plain"]
    assert cc[0].get(f"/admin/users/export.csv?chair={other_chair.id}", follow_redirects=False).status_code == 403
    with read_session() as r2:
        entries = list(r2.scalars(select(AuditLog).where(AuditLog.action == "export.users_csv")))
        assert len(entries) == 3 and entries[1].meta["q"] == "elsew"


def test_ledger_csv_route(gc, db, chair, price):
    u = factories.make_user(db, "Alice", chair)
    factories.add_events(db, u, "double")
    r = gc[0].get("/admin/exports/ledger.csv")
    rows = rows_of(r)
    assert rows[0][:3] == ["Date", "Type", "Name"] and rows[1][1:3] == ["double", "Alice"]
    assert rows[1][4:7] == ["2", "0,50", "1,00"]
    for bad in ("?from=not-a-date", "?from=2026-02-02&to=2026-01-01", "?chair=zzz"):
        assert "err=invalid_input" in gc[0].get("/admin/exports/ledger.csv" + bad, follow_redirects=False).headers["location"]
    empty = rows_of(gc[0].get("/admin/exports/ledger.csv?from=2000-01-01&to=2000-01-02"))
    assert len(empty) == 1
    with read_session() as r2:
        assert r2.scalars(select(AuditLog).where(AuditLog.action == "export.ledger_csv")).first().meta["rows"] == 1


def test_qr_page_content_has_only_the_two_urls_and_no_secrets(gc, monkeypatch, price):
    from tests.conftest import reload_settings
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://coffee.test")
    reload_settings()
    page = gc[0].get("/admin/qr").text
    assert "https://coffee.test/coffee/single" in page and "https://coffee.test/coffee/double" in page
    assert page.count("<svg") == 2 and "SINGLE" in page and "DOUBLE" in page and "€0.50" in page
    urls = set(re.findall(r"https?://[^\s\"'<>]+", page))
    assert urls <= {"https://coffee.test/coffee/single", "https://coffee.test/coffee/double"}
    for secret in ("test-secret-key-0123456789abcdef0123456789", "test-access-code"):
        assert secret not in page
    assert "coffee_session" not in page and "token" not in page.lower().replace("csrf_token", "")


def test_qr_free_text_line_is_printed_but_never_stored(gc, db):
    csrf = gc[1]
    r = gc[0].post("/admin/qr", data={"csrf_token": csrf, "line": "Access code: <b>kaffee-2026</b>"})
    assert r.status_code == 200 and "Access code: &lt;b&gt;kaffee-2026&lt;/b&gt;" in r.text  # escaped
    assert r.text.count("qr-line") >= 2
    with read_session() as r2:
        dump = " ".join(str(a.meta) for a in r2.scalars(select(AuditLog)))
    assert "kaffee-2026" not in dump
    assert "kaffee-2026" not in gc[0].get("/admin/qr").text  # not remembered


def test_print_stylesheet_exists_for_half_page_sheets():
    css = (ROOT / "static" / "admin.css").read_text()
    assert "@media print" in css and "48vh" in css and ".qr-label" in css


def test_user_content_is_escaped(gc, db, chair, price):
    u = factories.make_user(db, "<script>alert(1)</script>", chair)
    for path in ("/admin/users", f"/admin/users/{u.id}", "/admin"):
        text = gc[0].get(path).text
        assert "<script>alert(1)" not in text
    assert "&lt;script&gt;alert(1)" in gc[0].get("/admin/users").text


def test_admin_pages_are_not_cacheable_and_have_csp(gc):
    r = gc[0].get("/admin")
    assert "no-store" in r.headers["cache-control"]
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "'unsafe-inline'" not in csp and "frame-ancestors 'none'" in csp


def test_templates_have_no_inline_script_style_or_handlers():
    for path in glob.glob(str(ROOT / "templates" / "admin" / "*.html")):
        text = Path(path).read_text()
        assert not re.search(r"<script(?![^>]*\bsrc=)", text), path
        assert not re.search(r"\sstyle=", text), path
        assert not re.search(r"\son[a-z]+=", text), path
        assert not re.search(r"https?://", text), path  # no CDN / external assets


def test_every_referenced_admin_string_exists():
    catalog = CATALOGS["en"]
    keys = set()
    for path in glob.glob(str(ROOT / "templates" / "admin" / "*.html")) + glob.glob(str(ROOT / "app" / "web" / "admin_*.py")):
        for m in re.finditer(r"""\bt\(\s*["'](admin\.[a-z_.]*[a-z_])["']""", Path(path).read_text()):
            keys.add(m.group(1))
    keys = {k for k in keys if not k.endswith("_")}  # dynamic prefixes, covered below
    # keys with a dynamic suffix: build them from the known value sets
    dynamic = [f"admin.type.{x}" for x in ("single", "double", "reversal", "adjustment", "payment", "correction")]
    dynamic += [f"admin.status.{x}" for x in ("active", "inactive", "merged")]
    dynamic += [f"admin.users.sort_{x}" for x in ("balance", "name", "consumption", "activity")]
    dynamic += [f"admin.login.error.{x}" for x in ("invalid_login", "invalid_code", "rate_limited")]
    dynamic += [f"admin.csv.{x}" for x in ("name", "chair", "shots", "consumed", "paid", "balance", "last_activity",
                                         "status", "date", "type", "quantity", "unit_price", "amount", "note",
                                         "admin", "event_id")]
    missing = [k for k in sorted(keys | set(dynamic)) if k not in catalog]
    assert not missing, missing
    # every flash key used by redirects exists as msg/err string
    flash = set()
    for path in glob.glob(str(ROOT / "app" / "web" / "admin_*.py")):
        flash |= set(re.findall(r"""\b(?:msg|err)="([a-z_]+)"\)""", Path(path).read_text()))
    for key in flash:
        assert f"admin.msg.{key}" in catalog or f"admin.err.{key}" in catalog, key


def test_qr_svg_download_is_labeled_and_scoped(gc, cc, monkeypatch):
    r = gc[0].get("/admin/qr/double.svg")
    assert r.status_code == 200 and r.headers["content-type"].startswith("image/svg+xml")
    assert "attachment" in r.headers["content-disposition"]
    assert ">DOUBLE<" in r.text and "http://testserver/coffee/double" in r.text and "<script" not in r.text
    assert cc[0].get("/admin/qr/single.svg").status_code == 200  # every administrator may print the codes
    assert gc[0].get("/admin/qr/triple.svg").status_code == 404
    assert "/admin/qr/single.svg" in gc[0].get("/admin/qr").text

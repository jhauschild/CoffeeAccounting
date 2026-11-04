"""Task 4.5: head-admin dashboard tiles (mail card, banners, held by groups) and the four permanent QR codes."""

from __future__ import annotations

import re
from datetime import timedelta

import pytest
import segno
from sqlalchemy import func, select

from app.db import read_session, write_session
from app.models import AdminUser, AuditLog, ConsumptionEvent, PendingAction, User, UserSession
from app.services import exports, groups, ledger, mail, mail_credentials, mail_status
from app.strings import CATALOGS
from app.timeutil import utcnow
from tests import factories
from tests.admin_support import fast_hasher, login_as, make_real_admin, new_client  # noqa: F401
from tests.conftest import reload_settings

SMTP_USER = "coffee@lrz.test"
SECRET_PW = "Hunter2-very-secret-mail-pw"


@pytest.fixture(autouse=True)
def mail_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path / "secrets"))
    reload_settings()
    mail.reset_status()
    mail.clear_outbox()
    yield
    mail.reset_status()


@pytest.fixture
def head(app):
    admin_id, _ = make_real_admin(username="boss")
    c = new_client(app)
    return c, login_as(c, admin_id)


@pytest.fixture
def group_admin(app, chair):
    admin_id, _ = make_real_admin(role="chair", chairs=[chair], username="gadmin")
    c = new_client(app)
    return c, login_as(c, admin_id), admin_id


def persist(category, minutes_ago=0):
    with write_session() as w:
        mail_status.persist(w, category, now=utcnow() - timedelta(minutes=minutes_ago))


def smtp_backend(monkeypatch):
    monkeypatch.setenv("MAIL_BACKEND", "smtp")
    reload_settings()


# ----- mail card --------------------------------------------------------------------------------------------------


def test_card_not_configured_on_smtp_backend_shows_banner(head, monkeypatch):
    smtp_backend(monkeypatch)
    page = head[0].get("/admin").text
    assert "Mail configured" in page and "<dd>no</dd>" in page
    assert "Mail is not configured" in page and "setup-mail" in page
    assert "Last send OK" in page and "never" in page


def test_card_configured_shows_user_and_last_results_never_the_password(head, monkeypatch):
    smtp_backend(monkeypatch)
    mail_credentials.save_credentials(SMTP_USER, SECRET_PW)
    persist(None, minutes_ago=20)
    persist("auth", minutes_ago=5)
    page = head[0].get("/admin").text
    assert "<dd>yes</dd>" in page and SMTP_USER in page
    assert "Mail failing: auth." in page and "auth, " in page and "run setup-mail again" in page
    assert "Mail is not configured" not in page
    assert SECRET_PW not in page
    assert 'type="password"' not in page and "<form" not in page.split("mail-card-title")[1].split("held-tile-title")[0]


def test_card_cap_reached_banner_is_not_a_failure_banner(head, monkeypatch):
    smtp_backend(monkeypatch)
    mail_credentials.save_credentials(SMTP_USER, SECRET_PW)
    persist(None, minutes_ago=30)
    persist("cap_exceeded", minutes_ago=2)
    page = head[0].get("/admin").text
    assert "Mail cap reached" in page and "nothing is broken" in page and "30 mails per hour" in page
    assert "Mail failing" not in page
    persist(None)  # a successful send ends the banner
    assert "Mail cap reached" not in head[0].get("/admin").text


def test_card_unreadable_login_after_key_change(head, monkeypatch):
    smtp_backend(monkeypatch)
    mail_credentials.save_credentials(SMTP_USER, SECRET_PW)
    monkeypatch.setenv("SECRET_KEY", "a-completely-different-secret-key-0123456789")
    reload_settings()
    page = head[0].get("/admin").text  # the session cookie is a database row: it still works
    assert "cannot be read" in page and "<dd>no</dd>" in page and SECRET_PW not in page


def test_card_healthy_state_has_no_banner(head, monkeypatch):
    smtp_backend(monkeypatch)
    mail_credentials.save_credentials(SMTP_USER, SECRET_PW)
    persist(None)
    page = head[0].get("/admin").text
    assert 'role="alert"' not in page and SMTP_USER in page


def test_card_with_a_development_backend_needs_no_login_banner(head):
    page = head[0].get("/admin").text  # MAIL_BACKEND defaults to console in development
    assert "Backend" in page and "console" in page and "Mail is not configured" not in page


def test_card_status_is_read_from_the_shared_store_not_the_process(head, monkeypatch):
    """mail.get_status() is per process; the card shows what another process persisted."""
    smtp_backend(monkeypatch)
    mail_credentials.save_credentials(SMTP_USER, SECRET_PW)
    assert mail.get_status().last_failure_category is None
    persist("timeout")
    assert "Mail failing: timeout." in head[0].get("/admin").text


def test_server_send_result_reaches_the_card(head, monkeypatch):
    """A failed background send in the server process is what the dashboard then reports."""
    smtp_backend(monkeypatch)  # no stored login: the send fails with not_configured
    assert mail.send_in_background(mail.build_message(to="alice@tum.de", subject="Hi", body="x")) == "not_configured"
    page = head[0].get("/admin").text
    assert "not_configured, " in page and "alice@tum.de" not in page


# ----- group admins never see the mail or held tiles -------------------------------------------------------------


def test_group_admin_sees_neither_card_nor_tile_nor_banner(group_admin, monkeypatch):
    smtp_backend(monkeypatch)
    mail_credentials.save_credentials(SMTP_USER, SECRET_PW)
    persist("auth")
    page = group_admin[0].get("/admin").text
    for text in ("Mail configured", "Mail failing", "Mail is not configured", SMTP_USER, "Held by groups",
                 "/admin/groups", "setup-mail", "mail-card-title"):
        assert text not in page, text


def test_dashboard_context_is_not_even_built_for_a_group_admin(db, chair):
    from app.services import stats
    from app.services.errors import Forbidden

    gadmin = factories.make_admin(db, role="chair", chairs=[chair])
    with pytest.raises(Forbidden):
        with read_session() as r:
            stats.head_tiles(r, r.get(AdminUser, gadmin.id))


# ----- held by groups ---------------------------------------------------------------------------------------------


def money_in(page: str, title_id: str) -> str:
    section = page.split(f'id="{title_id}"')[1].split("</section>")[0]
    return re.search(r'<p class="big">(.*?)</p>', section, re.S).group(1)


def test_held_tile_equals_the_group_balances_sum(head, db, chair, other_chair, price):
    page = head[0].get("/admin").text
    assert money_in(page, "held-tile-title") == "€0.00" and 'href="/admin/groups"' in page
    ga1, _ = make_real_admin(role="chair", chairs=[chair], username="ga-one")
    ga2, _ = make_real_admin(role="chair", chairs=[other_chair], username="ga-two")
    u1 = factories.make_user(db, "Alice", chair)
    u2 = factories.make_user(db, "Bob", other_chair)
    with write_session() as w:
        ledger.add_payment(w, admin=w.get(AdminUser, ga1), user_id=u1.id, amount_cents=2500)
        ledger.add_payment(w, admin=w.get(AdminUser, ga2), user_id=u2.id, amount_cents=1325)
    with read_session() as r:
        expected = sum(row.held_cents for row in groups.list_group_balances(r))
    assert expected == 3825
    page = head[0].get("/admin").text
    assert money_in(page, "held-tile-title") == "€38.25"
    # a remittance lowers it, and the tile follows
    with write_session() as w:
        groups.record_remittance(w, head_admin=w.scalars(select(AdminUser).where(AdminUser.role == "global")).first(),
                                 group_admin_id=ga1, amount_cents=1000, idempotency_key="k1")
    with read_session() as r:
        expected = sum(row.held_cents for row in groups.list_group_balances(r))
    assert expected == 2825
    assert money_in(head[0].get("/admin").text, "held-tile-title") == "€28.25"


def test_held_tile_flags_a_negative_total_without_a_minus_sign(head, db, chair, price):
    ga, _ = make_real_admin(role="chair", chairs=[chair], username="ga-neg")
    with write_session() as w:
        groups.record_remittance(w, head_admin=w.scalars(select(AdminUser).where(AdminUser.role == "global")).first(),
                                 group_admin_id=ga, amount_cents=500, idempotency_key="k2")
    page = head[0].get("/admin").text
    assert money_in(page, "held-tile-title").startswith("€5.00") and "More handed over than collected" in page
    assert "-€5.00" not in page and "−€5.00" not in page


# ----- the four QR codes ------------------------------------------------------------------------------------------

KINDS = ("register", "single", "double", "website")
PATHS = {"register": "/register", "single": "/coffee/single", "double": "/coffee/double", "website": "/overview"}


def parse_svg_matrix(svg: str, label_height: int = 12, border: int = 4) -> list[list[bool]]:
    """Rebuild the module matrix from the SVG path (what a scanner sees)."""
    width = float(re.search(r'viewBox="0 0 ([\d.]+) ', svg).group(1))
    size = int(width) - 2 * border
    matrix = [[False] * size for _ in range(size)]
    for x, y, run in re.findall(r"M(\d+) (\d+)h(\d+)v1h-\d+z", svg):
        for dx in range(int(run)):
            matrix[int(y) - border - label_height][int(x) - border + dx] = True
    return matrix


def test_four_codes_with_the_permanent_urls(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://coffee.example.org")
    reload_settings()
    assert exports.qr_urls() == {k: f"https://coffee.example.org{p}" for k, p in PATHS.items()}


@pytest.mark.parametrize("kind", KINDS)
def test_every_svg_embeds_exactly_its_url(kind, monkeypatch, tmp_path):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://coffee.example.org")
    reload_settings()
    exports.write_qr_files(tmp_path)
    svg = (tmp_path / f"coffee-{kind}.svg").read_text(encoding="utf-8")
    url = f"https://coffee.example.org{PATHS[kind]}"
    assert f"<title>{kind.upper()}: {url}</title>" in svg and f">{url}<" in svg and f">{kind.upper()}<" in svg
    assert "<script" not in svg and "style=" not in svg and "href=" not in svg
    # the drawn modules are the QR code of exactly this URL (pure-Python decode check)
    expected = [[bool(v) for v in row] for row in segno.make(url, error="m", micro=False).matrix]
    assert parse_svg_matrix(svg) == expected


@pytest.mark.parametrize("with_label", [True, False])
@pytest.mark.parametrize("kind", KINDS)
def test_svg_module_matrix_equals_the_segno_matrix_with_and_without_label(kind, with_label, monkeypatch):
    """L-9: the dark modules drawn by `qr_svg` (path runs, quiet zone of 4, label offset when a label is shown)
    are exactly the segno matrix of the URL, for every one of the four URLs, standalone or inline."""
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://coffee.example.org")
    reload_settings()
    url = exports.qr_urls()[kind]
    expected = [[bool(v) for v in row] for row in segno.make(url, error="m", micro=False).matrix]
    for standalone in (True, False):
        svg = exports.qr_svg(url, kind.upper() if with_label else None, standalone=standalone)
        assert parse_svg_matrix(svg, label_height=12 if with_label else 0) == expected
        assert svg.count("<path") == 1 and ("xmlns=" in svg) == standalone
        assert (f">{kind.upper()}<" in svg) == with_label


def test_the_four_codes_are_four_different_matrices(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://coffee.example.org")
    reload_settings()
    urls = exports.qr_urls()
    assert len(set(urls.values())) == 4
    matrices = {kind: tuple(map(tuple, parse_svg_matrix(exports.qr_svg(url, None), label_height=0)))
                for kind, url in urls.items()}
    assert len(set(matrices.values())) == 4


@pytest.mark.parametrize("kind", KINDS)
def test_svg_decodes_with_opencv_when_available(kind, monkeypatch, tmp_path):
    cv2 = pytest.importorskip("cv2")
    np = pytest.importorskip("numpy")
    import io

    cairosvg = pytest.importorskip("cairosvg")  # only to rasterise; skipped cleanly when missing

    monkeypatch.setenv("PUBLIC_BASE_URL", "https://coffee.example.org")
    reload_settings()
    exports.write_qr_files(tmp_path)
    png = cairosvg.svg2png(bytestring=(tmp_path / f"coffee-{kind}.svg").read_bytes(), output_width=800)
    image = cv2.imdecode(np.frombuffer(io.BytesIO(png).getvalue(), np.uint8), cv2.IMREAD_GRAYSCALE)
    text, _, _ = cv2.QRCodeDetector().detectAndDecode(image)
    assert text == f"https://coffee.example.org{PATHS[kind]}"


def test_qr_page_lists_four_labeled_sheets_and_downloads(head, group_admin, price):
    page = head[0].get("/admin/qr").text
    assert page.count('class="qr-sheet card"') == 4 and page.count("<svg") == 4
    for kind in KINDS:
        assert f'data-qr="{kind}"' in page and f"/admin/qr/{kind}.svg" in page and kind.upper() in page
        r = head[0].get(f"/admin/qr/{kind}.svg")
        assert r.status_code == 200 and f"http://testserver{PATHS[kind]}" in r.text
        assert group_admin[0].get(f"/admin/qr/{kind}.svg").status_code == 200  # every administrator may print
    assert head[0].get("/admin/qr/other.svg").status_code == 404
    assert group_admin[0].get("/admin/qr").status_code == 200


def test_price_is_printed_on_the_shot_codes_only(head, price):
    page = head[0].get("/admin/qr").text
    sheets = {m.group(1): m.group(0) for m in re.finditer(r'<section class="qr-sheet card".*?data-qr="(\w+)".*?</section>', page, re.S)}
    assert set(sheets) == set(KINDS)
    assert "qr-price" in sheets["single"] and "qr-price" in sheets["double"]
    assert "qr-price" not in sheets["register"] and "qr-price" not in sheets["website"]


def test_free_text_line_is_escaped_unstored_and_unlogged(head, db):
    r = head[0].post("/admin/qr", data={"csrf_token": head[1], "line": "<img src=x onerror=alert(1)> Bring your own cup"})
    assert r.status_code == 200 and "&lt;img src=x onerror=alert(1)&gt; Bring your own cup" in r.text
    assert "<img src=x" not in r.text and r.text.count('class="qr-line"') == 4  # printed on every sheet
    with read_session() as r2:
        assert "own cup" not in " ".join(str(a.meta) for a in r2.scalars(select(AuditLog)))
    assert "own cup" not in head[0].get("/admin/qr").text


def test_print_stylesheet_puts_two_codes_on_a_page():
    css = (re.sub(r"\s+", " ", open("static/admin.css", encoding="utf-8").read()))
    assert "@media print" in css and "height: 48vh" in css
    assert ".qr-sheet:nth-of-type(2n+1):not(:first-of-type)" in css and "break-before: page" in css


def test_no_access_code_wording_anywhere_in_the_admin_strings_and_templates():
    texts = [v for k, v in CATALOGS["en"].items() if k.startswith("admin.")]
    import glob

    for path in glob.glob("templates/admin/*.html"):
        texts.append(open(path, encoding="utf-8").read())
    assert not [x for x in texts if re.search(r"access[ _-]?code", x, re.I)]


# ----- the register code never records a coffee -----------------------------------------------------------------


def counts():
    with read_session() as r:
        return tuple(r.scalar(select(func.count()).select_from(model)) for model in
                     (ConsumptionEvent, PendingAction, User, UserSession, AuditLog))


def test_register_url_writes_nothing_anonymous(client, price):
    before = counts()
    for _ in range(2):
        r = client.get(PATHS["register"])
        assert r.status_code == 200
    assert counts() == before


def test_register_url_writes_nothing_when_signed_in(client, db, chair, price):
    user = factories.make_member(db, "Alice", chair)
    factories.make_session(db, user, raw_token="user-session-token-0123456789")
    client.cookies.set("coffee_session", "user-session-token-0123456789")
    before = counts()
    r = client.get(PATHS["register"], follow_redirects=False)
    assert r.status_code in (200, 303)
    assert counts() == before


def test_website_url_never_records_a_coffee(client, price):
    """Anonymous visitors are sent to sign in; only a `view_site` pending action may be stored, never a coffee."""
    before = counts()
    assert client.get(PATHS["website"]).status_code == 200  # followed through to /login
    after = counts()
    assert after[0] == before[0] == 0 and after[2:] == before[2:]  # no consumption, users, sessions, audit rows
    with read_session() as r:
        assert set(r.scalars(select(PendingAction.kind))) <= {"view_site"}

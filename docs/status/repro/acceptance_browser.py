"""Acceptance run (task 7.3): the user and admin journeys in a REAL browser (headless Chromium via Playwright), plus
decoding of the four QR codes from what Chromium renders.

    python docs/status/repro/acceptance_browser.py --name prod --base https://localhost:18443 --db WORK/prod/data/coffee.db \
        --mail-dir WORK/relay/messages --repo WORK/prod --qr WORK/results-prod.qr.json --shots WORK/shots-prod \
        [--cvdeps DIR_WITH_cv2] --head-password '...'

Journey (phone-sized viewport 390x844): register a member through the form, read the mail the instance sent, open the
link, confirm, scan the Single QR target (JS auto-submit), see the receipt, reload and go Back (no second coffee),
scan Double, open the site. A second browser context is the admin: sign in, enrol TOTP (secret read from the page),
open the person, record a payment through the confirm page; a fresh sign-in shows the code field and a typed TOTP code
books a second payment. The four SVG codes downloaded from /admin/qr are rendered in Chromium and decoded with OpenCV
(optional: --cvdeps points at a directory holding cv2). Every check cross-checks SQLite. Exit 0 only if all pass.
Never runs `playwright install`; uses the pre-installed browser.
"""

from __future__ import annotations

import argparse
import base64
import email
import email.policy
import json
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pyotp

ap = argparse.ArgumentParser()
ap.add_argument("--name", required=True)
ap.add_argument("--base", required=True)
ap.add_argument("--db", required=True)
ap.add_argument("--mail-dir", required=True)
ap.add_argument("--repo", required=True)
ap.add_argument("--qr", required=True)
ap.add_argument("--shots", required=True)
ap.add_argument("--cvdeps", default="")
ap.add_argument("--head-password", required=True)
ARGS = ap.parse_args()
BASE = ARGS.base.rstrip("/")
SHOTS = Path(ARGS.shots)
SHOTS.mkdir(parents=True, exist_ok=True)
MAIL = Path(ARGS.mail_dir)
results = []
PW = "Browser-User-Password-8123"


def check(section, name, ok, detail=""):
    results.append({"section": section, "check": name, "ok": bool(ok), "detail": str(detail)[:400]})
    print(("PASS " if ok else "FAIL ") + f"[{section}] {name}" + (f" -- {str(detail)[:300]}" if detail and not ok else ""), flush=True)
    return bool(ok)


def q(query, *p):
    con = sqlite3.connect(ARGS.db, timeout=30)
    try:
        return con.execute(query, p).fetchall()
    finally:
        con.close()


def mails():
    out = []
    for p in sorted(MAIL.glob("*.eml")):
        m = email.message_from_bytes(p.read_bytes(), policy=email.policy.default)
        body = m.get_body(("plain",))
        out.append((m["To"] and m["To"].addresses[0].addr_spec, body.get_content() if body else ""))
    return out


def wait_link(addr, before, kind):
    for _ in range(120):
        for to, body in mails()[before:]:
            if to == addr:
                m = re.search(rf"{re.escape(BASE)}/{kind}/[A-Za-z0-9_\-]+", body)
                if m:
                    return m.group(0)
        time.sleep(0.25)
    return None


def launch_chromium(p):
    """Playwright's own revision first, then whatever pre-installed Chromium exists (never `playwright install`)."""
    import os
    root = Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers"))
    candidates = [None] + [str(x) for x in sorted(root.glob("chromium_headless_shell-*/chrome-linux/headless_shell")) + sorted(root.glob("chromium-*/chrome-linux/chrome"))]
    error = None
    for exe in candidates:
        try:
            return p.chromium.launch(executable_path=exe, args=["--no-sandbox"])
        except Exception as exc:  # noqa: BLE001
            error = exc
    raise SystemExit(f"no Chromium could be launched: {error}")


def main():
    from playwright.sync_api import sync_playwright

    suffix = str(int(time.time()))[-5:]
    uname, email_addr = f"browser{suffix}", f"browser{suffix}@tum.de"
    with sync_playwright() as p:
        browser = launch_chromium(p)
        phone = dict(viewport={"width": 390, "height": 844}, device_scale_factor=2, ignore_https_errors=True, is_mobile=True)
        # --- the four QR codes: render what the admin page serves, decode with OpenCV -----------------------------
        qr = json.loads(Path(ARGS.qr).read_text())
        if ARGS.cvdeps:
            sys.path.insert(0, ARGS.cvdeps)
        try:
            import cv2
            import numpy as np
        except ImportError:
            cv2 = None
        if cv2 is None:
            check("qr", "OpenCV available for QR decoding", False, "pass --cvdeps")
        else:
            ctx = browser.new_context(viewport={"width": 700, "height": 700})
            page = ctx.new_page()
            want = {"register": BASE + "/register", "single": BASE + "/coffee/single", "double": BASE + "/coffee/double", "website": BASE + "/overview"}
            for kind, svg in sorted(qr["svgs"].items()):
                b64 = base64.b64encode(svg.encode()).decode()
                page.set_content(f'<body style="margin:0;background:#fff"><img style="width:600px;height:600px;margin:50px" src="data:image/svg+xml;base64,{b64}"></body>')
                png = SHOTS / f"qr-{kind}.png"
                page.screenshot(path=str(png))
                img = cv2.imdecode(np.frombuffer(png.read_bytes(), np.uint8), cv2.IMREAD_COLOR)
                text, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
                check("qr", f"QR '{kind}' rendered in Chromium decodes to {want[kind]}", text == want[kind], repr(text))
            ctx.close()

        # --- member journey ---------------------------------------------------------------------------------------
        ctx = browser.new_context(**phone)
        page = ctx.new_page()
        chair_before = q("select count(*) from chairs")[0][0]
        page.goto(BASE + "/register")
        page.screenshot(path=str(SHOTS / "register.png"), full_page=True)
        page.fill("#username", uname)
        page.fill("#display_name", "Browser Person")
        page.select_option("#chair_id", index=1)
        page.fill("#email", email_addr)
        page.fill("#password", PW)
        page.fill("#password2", PW)
        page.check("#privacy_ack")
        before = len(mails())
        page.click("button[type=submit]")
        page.wait_for_load_state()
        page.screenshot(path=str(SHOTS / "register-submitted.png"), full_page=True)
        link = wait_link(email_addr, before, "verify")
        check("browser", "registering through the form mails a verification link", link is not None)
        check("browser", "no user exists before the link is confirmed", q("select count(*) from users where username=?", uname)[0][0] == 0)
        page.goto(link)
        page.screenshot(path=str(SHOTS / "verify.png"), full_page=True)
        check("browser", "opening the link writes nothing (confirm page)", q("select count(*) from users where username=?", uname)[0][0] == 0)
        page.click("button[type=submit]")
        page.wait_for_load_state()
        check("browser", "confirming creates the member and signs the browser in", q("select account_kind from users where username=?", uname) == [("member",)] and "/login" not in page.url, page.url)
        page.screenshot(path=str(SHOTS / "after-verify.png"), full_page=True)
        uid = q("select id from users where username=?", uname)[0][0]
        n0 = q("select count(*) from consumption_events where user_id=?", uid)[0][0]
        page.goto(BASE + "/coffee/single")  # data-autosubmit: scan.js posts the form
        page.wait_for_url(re.compile(r".*/coffee/done/.*"), timeout=15000)
        page.screenshot(path=str(SHOTS / "receipt.png"), full_page=True)
        n1 = q("select count(*) from consumption_events where user_id=?", uid)[0][0]
        check("browser", "scanning the Single QR target records one coffee (JS auto-submit), receipt page shown", n1 == n0 + 1, page.url)
        body = page.inner_text("body")
        check("browser", "receipt shows the amount owed in words and the shots this month", ("Outstanding" in body or "Credit" in body or "All settled" in body) and "Shots this month" in body, body[:200])
        done_url = page.url
        page.reload()
        check("browser", "reloading the receipt records nothing", q("select count(*) from consumption_events where user_id=?", uid)[0][0] == n1)
        page.goto(BASE + "/overview")
        page.go_back()
        page.go_forward()
        check("browser", "Back/Forward through the receipt records nothing", q("select count(*) from consumption_events where user_id=?", uid)[0][0] == n1)
        page.goto(BASE + "/coffee/double")
        page.wait_for_url(re.compile(r".*/coffee/done/.*"), timeout=15000)
        last = q("select quantity, amount_cents, unit_price_cents from consumption_events where user_id=? order by created_at desc limit 1", uid)[0]
        check("browser", "scanning Double records 2 shots at 2 x the price", last[0] == 2 and last[1] == 2 * last[2], last)
        # undo via the button on the success page
        page.click("button:has-text(\"Undo this coffee\")")
        page.wait_for_load_state()
        check("browser", "the Undo button appends a reversal (-2 shots) and deletes nothing", q("select count(*) from consumption_events where user_id=? and quantity=-2", uid)[0][0] == 1 and
              q("select count(*) from consumption_events where user_id=? and quantity=2", uid)[0][0] == 1)
        for path, shot in (("/overview", "site-overview"), ("/overview/people", "site-people"), ("/overview/chairs", "site-chairs"), ("/account", "account")):
            page.goto(BASE + path)
            page.screenshot(path=str(SHOTS / f"{shot}.png"), full_page=True)
            check("browser", f"signed-in member opens {path}", page.url.endswith(path) and page.locator("h1").count() > 0, page.url)
        overflow = page.evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth")
        check("browser", "no horizontal overflow on the phone-sized site page (390 px)", not overflow)
        csp_errors = []
        page.on("console", lambda m: csp_errors.append(m.text) if "Content Security Policy" in m.text else None)
        page.goto(BASE + "/overview/people")
        check("browser", "no Content-Security-Policy violation logged in the console", not csp_errors, csp_errors[:2])
        ctx.close()

        # --- admin journey ----------------------------------------------------------------------------------------
        admin_name, admin_pw = f"webhead{suffix}", ARGS.head_password
        r = subprocess.run([sys.executable, "-m", "app.cli", "create-admin", "--username", admin_name, "--role", "global", "--password-stdin"], input=admin_pw + "\n",
                           text=True, capture_output=True, cwd=ARGS.repo, env=cli_env())
        check("browser", "create-admin (CLI, password on stdin) creates a second head admin for the browser run", r.returncode == 0, r.stderr + r.stdout)
        actx = browser.new_context(viewport={"width": 1100, "height": 900}, ignore_https_errors=True)
        ap_ = actx.new_page()
        ap_.goto(BASE + "/admin/login")
        ap_.fill("#username", admin_name)
        ap_.fill("#password", admin_pw)
        ap_.click("button[type=submit]")
        ap_.wait_for_load_state()
        check("browser", "admin password login lands on the TOTP enrolment page", "/admin/totp/setup" in ap_.url, ap_.url)
        secret = re.sub(r"\s+", "", ap_.inner_text("code.secret"))
        ap_.screenshot(path=str(SHOTS / "admin-totp-setup.png"), full_page=True)
        used = set()
        code = pyotp.TOTP(secret).now()
        used.add(code)
        ap_.fill("#code", code)
        ap_.click("form[action='/admin/totp/setup'] button[type=submit]")
        ap_.wait_for_load_state()
        check("browser", "enrolment with a code typed in the browser shows the recovery codes", len(re.findall(r"\b[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}\b", ap_.inner_text("body"))) == 8)
        ap_.screenshot(path=str(SHOTS / "admin-recovery.png"), full_page=True)
        ap_.goto(BASE + f"/admin/users/{str(__import__('uuid').UUID(uid))}")
        ap_.screenshot(path=str(SHOTS / "admin-person.png"), full_page=True)
        pays0 = q("select count(*) from payment_events where user_id=?", uid)[0][0]
        ap_.fill("#pay_amount", "5,00")
        ap_.fill("#pay_note", "browser payment")
        ap_.click("form[action$='/payment'] button[type=submit]")
        ap_.wait_for_load_state()
        ap_.screenshot(path=str(SHOTS / "admin-confirm.png"), full_page=True)
        check("browser", "a payment form shows the confirm page first: nothing booked yet", q("select count(*) from payment_events where user_id=?", uid)[0][0] == pays0 and "/admin/stepup/confirm" in ap_.content())
        window_open = ap_.locator("#code").count() == 0
        check("browser", "right after enrolment the window is open: no code field", window_open)
        ap_.click("form[action='/admin/stepup/confirm'] button[type=submit]")
        ap_.wait_for_load_state()
        check("browser", "confirm books the 5.00 payment", q("select amount_cents, kind from payment_events where user_id=? and note='browser payment'", uid) == [(500, "cash")], q("select amount_cents from payment_events where user_id=?", uid))
        ap_.screenshot(path=str(SHOTS / "admin-after-pay.png"), full_page=True)
        # fresh sign-in: window closed, code typed in the browser
        ap_.click("form[action='/admin/logout'] button[type=submit]")
        ap_.wait_for_load_state()
        ap_.goto(BASE + "/admin/login")
        ap_.fill("#username", admin_name)
        ap_.fill("#password", admin_pw)
        ap_.click("button[type=submit]")
        ap_.wait_for_load_state()
        check("browser", "later sign-in is password only (no TOTP prompt at login)", ap_.url.rstrip("/").endswith("/admin"), ap_.url)
        ap_.goto(BASE + f"/admin/users/{str(__import__('uuid').UUID(uid))}")
        ap_.fill("#pay_amount", "1,50")
        ap_.fill("#pay_note", "browser payment 2")
        ap_.click("form[action$='/payment'] button[type=submit]")
        ap_.wait_for_load_state()
        check("browser", "fresh session: the confirm page asks for a code", ap_.locator("#code").count() == 1)
        ap_.fill("#code", "000000")
        ap_.click("form[action='/admin/stepup/confirm'] button[type=submit]")
        ap_.wait_for_load_state()
        check("browser", "a wrong code books nothing", q("select count(*) from payment_events where note='browser payment 2'")[0][0] == 0)
        ap_.screenshot(path=str(SHOTS / "admin-wrong-code.png"), full_page=True)
        while True:
            c2 = pyotp.TOTP(secret).now()
            if c2 not in used:
                break
            time.sleep(1)
        if ap_.locator("#code").count() == 0:  # the wrong-code page may have been a redirect: redo the preview
            ap_.goto(BASE + f"/admin/users/{str(__import__('uuid').UUID(uid))}")
            ap_.fill("#pay_amount", "1,50")
            ap_.fill("#pay_note", "browser payment 2")
            ap_.click("form[action$='/payment'] button[type=submit]")
            ap_.wait_for_load_state()
        ap_.fill("#code", c2)
        ap_.click("form[action='/admin/stepup/confirm'] button[type=submit]")
        ap_.wait_for_load_state()
        check("browser", "the correct code typed in the browser books the second payment", q("select count(*) from payment_events where note='browser payment 2'")[0][0] == 1)
        # balance on the person page equals SQL
        bal = q("select coalesce((select sum(amount_cents) from consumption_events where user_id=?),0) - coalesce((select sum(amount_cents) from payment_events where user_id=?),0)", uid, uid)[0][0]
        ap_.goto(BASE + f"/admin/users/{str(__import__('uuid').UUID(uid))}")
        txt = ap_.inner_text("body")
        shown = f"{abs(bal) // 100}.{abs(bal) % 100:02d}"
        check("browser", "the person page balance equals the SQL balance (credit after 6.50 paid)", shown in txt.replace(",", ".") and bal < 0, (bal, txt[:150]))
        ap_.goto(BASE + "/admin/qr")
        ap_.screenshot(path=str(SHOTS / "admin-qr.png"), full_page=True)
        ap_.goto(BASE + "/admin")
        ap_.screenshot(path=str(SHOTS / "admin-dashboard.png"), full_page=True)
        actx.close()
        browser.close()
    Path(ARGS.shots, "results.json").write_text(json.dumps(results, indent=1))
    failed = [r for r in results if not r["ok"]]
    print(f"\n{len(results)} checks, {len(failed)} FAILED (browser {ARGS.name})")
    return 1 if failed else 0


def cli_env():
    import os
    env = dict(os.environ)
    env["PATH"] = str(Path(sys.executable).parent) + ":" + env["PATH"]
    return env


if __name__ == "__main__":
    raise SystemExit(main())

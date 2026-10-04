"""Authorization of EVERY /admin route: anonymous, normal-user session, out-of-scope chair admin,
in-scope chair admin and global admin. The route list comes from the routers (and is cross-checked
against the OpenAPI paths of the real app), so a new route without a policy fails this test."""

from __future__ import annotations

import pytest

from app.web import admin_deps as ad
from app.web import admin_groups, admin_login, admin_manage, admin_roles, admin_stepup, admin_users
from tests import factories
from tests.admin_support import fast_hasher, login_as, make_real_admin, new_client  # noqa: F401

PUBLIC = {("GET", "/admin/login"), ("POST", "/admin/login")}


def _calls(dependant):
    yield dependant.call
    for sub in dependant.dependencies:
        yield from _calls(sub)


def collect_routes():
    found = []
    for module in (admin_login, admin_users, admin_groups, admin_roles, admin_stepup, admin_manage):
        for route in module.router.routes:
            for method in route.methods - {"HEAD", "OPTIONS"}:
                found.append((method, "/admin" + route.path, set(_calls(route.dependant))))
    return found


def policy_of(method, path, calls):
    if (method, path) in PUBLIC:
        return "public"
    if ad.require_global_admin in calls or ad.global_user_access in calls:
        policy = "global-user" if ad.global_user_access in calls else "global"
    elif ad.admin_user_access in calls:
        policy = "user"
    elif ad.require_admin in calls:
        policy = "admin"
    elif ad.live_admin_session in calls:
        policy = "session"  # logout and the one-time TOTP enrolment: reachable before enrolment
    else:
        policy = None
    return policy


ROUTES = collect_routes()
IDS = [f"{m} {p}" for m, p, _ in ROUTES]

POST_DATA = {
    "/admin/logout": {},
    "/admin/totp/setup": {"code": "000000"},
    "/admin/account/password": {"current_password": "x" * 12, "new_password": "y" * 14, "new_password2": "y" * 14},
    "/admin/account/sessions/revoke": {},
    "/admin/users/{user_id}/payment": {"amount": "5"},
    "/admin/users/{user_id}/adjustment": {"quantity": "1"},
    "/admin/users/{user_id}/events/{event_id}/reverse": {},
    "/admin/users/{user_id}/rename": {"display_name": "Renamed"},
    "/admin/users/{user_id}/chair": {"chair_id": "{other_chair_id}"},
    "/admin/users/{user_id}/status": {"active": "0"},
    "/admin/users/{user_id}/sessions/revoke": {},
    "/admin/users/{user_id}/merge": {"target_id": "{user2_id}"},
    "/admin/chairs": {"full_name": "New chair", "short_name": "NEW"},
    "/admin/chairs/{chair_id}/rename": {"full_name": "Renamed chair", "short_name": "REN"},
    "/admin/chairs/{chair_id}/active": {"active": "1"},
    "/admin/prices": {"price": "0.60"},
    "/admin/qr": {"line": "hello"},
    "/admin/users/{user_id}/balance": {"amount": "5", "direction": "owes"},
    "/admin/groups/remittances": {"group_admin_id": "{group_admin_id}", "amount": "5"},
    "/admin/groups/remittances/{remittance_id}/correct": {"corrected_to": "4"},
    "/admin/users/{user_id}/group-admin/promote": {},
    "/admin/users/{user_id}/group-admin/demote": {},
    "/admin/users/{user_id}/sponsor": {"sponsor_id": "{user2_id}"},
    "/admin/stepup/confirm": {"payload": "not-a-payload", "nonce": "x"},
}

CONFIRM = "/admin/stepup/confirm"


def test_every_admin_route_has_a_policy_and_csrf_on_posts():
    assert len(ROUTES) >= 30
    for method, path, calls in ROUTES:
        assert policy_of(method, path, calls) is not None, f"{method} {path} has no authorization dependency"
        if method == "POST" and (method, path) not in PUBLIC:
            assert ad.require_admin_csrf in calls, f"{method} {path} lacks the CSRF dependency"
            assert path in POST_DATA, f"add form data for {path} to POST_DATA"
        if method == "POST" and (method, path) in PUBLIC:
            assert ad.verify_login_csrf in calls


# POST routes that do NOT change a balance. Everything else must declare `require_stepup`. Adding a POST route
# here is a deliberate statement that it books no money: a new balance-changing route that is not listed
# fails `test_every_post_route_is_allow_listed_or_requires_stepup`.
NON_BALANCE_POSTS = {
    "/admin/login", "/admin/logout", "/admin/totp/setup",             # authentication, TOTP enrolment
    "/admin/account/password", "/admin/account/sessions/revoke",       # password change, own sessions
    "/admin/users/{user_id}/rename", "/admin/users/{user_id}/chair", "/admin/users/{user_id}/status",
    "/admin/users/{user_id}/sessions/revoke",                           # profile, chair change, deactivation
    "/admin/chairs", "/admin/chairs/{chair_id}/rename", "/admin/chairs/{chair_id}/active",
    "/admin/prices", "/admin/qr",                                       # chairs, price change, QR preview
    "/admin/users/{user_id}/group-admin/promote", "/admin/users/{user_id}/group-admin/demote",
    "/admin/users/{user_id}/sponsor",                                   # role assignment, sponsor change (task 4.3)
}
# Entry forms of the step-up actions: they only PREVIEW (a rolled-back dry run) and render the confirm page.
PREVIEW_POSTS = {
    "/admin/users/{user_id}/payment", "/admin/users/{user_id}/adjustment",
    "/admin/users/{user_id}/events/{event_id}/reverse", "/admin/users/{user_id}/merge",
    "/admin/users/{user_id}/balance", "/admin/groups/remittances",
    "/admin/groups/remittances/{remittance_id}/correct",
}
STEPUP_POSTS = {"/admin/stepup/confirm"}


def test_every_post_route_is_allow_listed_or_requires_stepup():
    post_paths = {p for m, p, _ in ROUTES if m == "POST"}
    assert NON_BALANCE_POSTS | PREVIEW_POSTS | STEPUP_POSTS == post_paths, \
        "a POST route is neither allow-listed as non-balance nor declares require_stepup"
    for method, path, calls in ROUTES:
        if method != "POST":
            continue
        if path in NON_BALANCE_POSTS or path in PREVIEW_POSTS:
            assert ad.require_stepup not in calls, path
        else:
            assert ad.require_stepup in calls, f"{path} changes balances and must depend on require_stepup"
            assert ad.require_admin_csrf in calls, path
    assert not (NON_BALANCE_POSTS & PREVIEW_POSTS) and not (NON_BALANCE_POSTS & STEPUP_POSTS)


BALANCE_SERVICE_NAMES = frozenset({"add_payment", "add_adjustment", "admin_reverse_event", "merge_users",
                                   "set_balance", "record_remittance"})
# Modules under app/web that may reference the balance-changing services. EMPTY on purpose: the only executor is
# app/services/stepup.py (a service module behind `require_stepup`, not a web module), so it is not scanned here.
WEB_ALLOW_LIST: frozenset[str] = frozenset()
_SERVICE_MODULES = ("ledger", "users", "groups")


def balance_service_references(source: str) -> list[str]:
    """Every way a module can reach a balance-changing service function, found on the AST (not on call sites):
    `from x import add_payment [as _ap]`, `import x as y`-style module attribute access (`ledger.add_payment`,
    `y.ledger.set_balance`), a bare name, `getattr(mod, "add_payment")`, and star imports from the service modules. Aliasing cannot hide an import because the imported NAME is checked."""
    import ast

    hits: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name in BALANCE_SERVICE_NAMES:
                    hits.append(f"line {node.lineno}: imports {alias.name} (as {alias.asname or alias.name})")
                elif alias.name == "*" and (node.module or "").rsplit(".", 1)[-1] in _SERVICE_MODULES:
                    hits.append(f"line {node.lineno}: star import from {node.module}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.rsplit(".", 1)[-1] in BALANCE_SERVICE_NAMES:
                    hits.append(f"line {node.lineno}: imports {alias.name}")
        elif isinstance(node, ast.Attribute) and node.attr in BALANCE_SERVICE_NAMES:
            hits.append(f"line {node.lineno}: attribute access .{node.attr}")
        elif isinstance(node, ast.Name) and node.id in BALANCE_SERVICE_NAMES:
            hits.append(f"line {node.lineno}: name {node.id}")
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr"
              and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)
              and node.args[1].value in BALANCE_SERVICE_NAMES):
            hits.append(f"line {node.lineno}: getattr(..., {node.args[1].value!r})")
    return hits


def test_balance_services_are_only_called_from_the_step_up_registry():
    """No app/web module may import or reference a balance-changing service function, under any alias: the only
    executor is app/services/stepup.py behind `require_stepup` (a service, not a web module, hence not scanned)."""
    from pathlib import Path
    from app.services import stepup
    web = Path(__file__).resolve().parent.parent / "app" / "web"
    files = sorted(web.rglob("*.py"))
    assert files, "the scan found no web modules"
    offenders = {f.name: hits for f in files if f.name not in WEB_ALLOW_LIST
                 and (hits := balance_service_references(f.read_text()))}
    assert offenders == {}, f"balance-changing services referenced outside the step-up registry: {offenders}"
    assert set(stepup.REGISTRY) >= {"payment", "adjustment", "reversal", "merge", "set_balance", "remittance",
                                    "remittance_correction"}
    assert (Path(stepup.__file__).resolve().parent.name, Path(stepup.__file__).name) == ("services", "stepup.py")


def test_the_balance_scan_catches_aliased_imports_and_attribute_access():
    aliased = "from app.services.ledger import add_payment as _ap\n\ndef f(db):\n    return _ap(db)\n"
    assert balance_service_references(aliased)
    assert balance_service_references("from app.services import ledger as L\nL.set_balance(1)\n")
    assert balance_service_references("import app.services.groups as g\ng.record_remittance(1)\n")
    assert balance_service_references("from app.services.users import *\n")
    assert balance_service_references("fn = getattr(mod, 'merge_users')\n")
    assert balance_service_references("from app.services.ledger import admin_reverse_event\n")
    assert balance_service_references("add_adjustment(db, 1)\n")
    # unrelated code and read-only service functions are fine
    assert not balance_service_references("from app.services.ledger import get_totals, recent_payments\n"
                                          "x = get_totals(1)\n")
    assert not balance_service_references("from app.services import stepup\nstepup.authorise(1)\n")


def test_route_list_matches_the_real_app(app):
    """Nothing under /admin exists outside the routers enumerated above."""
    spec = app.openapi()["paths"]
    real = {(m.upper(), p) for p, item in spec.items() if p.startswith("/admin") for m in item}
    assert real == {(m, p) for m, p, _ in ROUTES}


@pytest.fixture
def world(db, chair, other_chair, price):
    user = factories.make_user(db, "Alice", chair)
    user2 = factories.make_user(db, "Alice Two", chair)
    other_user = factories.make_user(db, "Bob", other_chair)
    event = factories.add_events(db, user, "single")[0]
    factories.make_payment(db, user, factories.make_admin(db, "global"), 100)
    from app.services import groups, ledger
    head = factories.make_admin(db, "global")
    ga = factories.make_admin(db, "chair", [chair])
    ledger.add_payment(db, admin=ga, user_id=user.id, amount_cents=1000)
    remittance = groups.record_remittance(db, head_admin=head, group_admin_id=ga.id, amount_cents=300,
                                          idempotency_key="world-remit")
    db.commit()
    ids = {"user_id": user.id, "user2_id": user2.id, "event_id": event.id, "chair_id": chair.id,
           "other_chair_id": other_chair.id, "other_user_id": other_user.id, "kind": "single",
           "group_admin_id": ga.id, "remittance_id": remittance.id}
    return ids


@pytest.fixture
def principals(app, chair, other_chair):
    """name -> (client, csrf)."""
    out = {}
    for name, role, chairs in (("global", "global", ()), ("in_scope", "chair", [chair]),
                               ("out_of_scope", "chair", [other_chair])):
        admin_id, _ = make_real_admin(role=role, chairs=chairs, username=name)
        c = new_client(app)
        out[name] = (c, login_as(c, admin_id))
    return out


def fill(template: str, ids: dict) -> str:
    for key, value in ids.items():
        template = template.replace("{" + key + "}", str(value))
    return template


def call(client, method, path, ids, csrf=None):
    url = fill(path, ids)
    if method == "GET":
        return client.get(url, follow_redirects=False)
    data = {k: fill(v, ids) for k, v in POST_DATA[path].items()}
    if csrf is not None:
        data["csrf_token"] = csrf
    return client.post(url, data=data, follow_redirects=False)


def rejected_as_anonymous(r):
    return r.status_code in (303, 403) and (r.status_code == 403 or r.headers["location"] == "/admin/login")


@pytest.mark.parametrize("method,path,calls", ROUTES, ids=IDS)
def test_anonymous_and_normal_users_are_rejected(method, path, calls, app, world, db, chair, login, client):
    policy = policy_of(method, path, calls)
    if policy == "public":
        r = call(client, method, path, world) if method == "GET" else client.post(path, data={}, follow_redirects=False)
        assert r.status_code in (200, 403)  # login form / login without CSRF token
        return
    anonymous = new_client(app)
    r = call(anonymous, method, path, world, csrf="whatever")
    assert r.status_code == 303 and r.headers["location"] == "/admin/login", (r.status_code, r.text[:100])
    login(factories.make_user(db, "Normal Person", chair))  # a normal-user session on `client`
    r = call(client, method, path, world, csrf="whatever")
    assert r.status_code == 303 and r.headers["location"] == "/admin/login"


@pytest.mark.parametrize("method,path,calls", ROUTES, ids=IDS)
def test_scope_and_role_enforced(method, path, calls, world, principals):
    policy = policy_of(method, path, calls)
    if policy in ("public", "session"):
        return  # login, enrolment and logout routes are covered by the login tests and the enrolment-gate test below
    allowed = {"admin": {"global", "in_scope", "out_of_scope"}, "user": {"global", "in_scope"},
               "global": {"global"}, "global-user": {"global"}}[policy]
    for name in ("out_of_scope", "in_scope", "global"):  # the mutating principals last
        client, csrf = principals[name]
        r = call(client, method, path, world, csrf=csrf)
        if path == CONFIRM:  # authorised admins reach the step-up check, which rejects the bogus payload
            assert r.status_code == 400 and "stepup" not in r.headers.get("location", ""), (name, r.status_code)
            continue
        if name in allowed:
            assert r.status_code in (200, 303), (name, r.status_code, r.text[:200])
            assert r.headers.get("location") != "/admin/login", name
        else:
            assert r.status_code == 403, (name, r.status_code)


def test_global_admin_sees_all_chairs_chair_admin_only_theirs(world, principals, chair, other_chair):
    g, _ = principals["global"]
    ca, _ = principals["in_scope"]
    cb, _ = principals["out_of_scope"]
    assert "Bob" in g.get("/admin/users").text and "Alice" in g.get("/admin/users").text
    assert "Bob" not in ca.get("/admin/users").text and "Alice" in ca.get("/admin/users").text
    assert "Alice" not in cb.get("/admin/users").text and "Bob" in cb.get("/admin/users").text
    assert ca.get(f"/admin/users?chair={other_chair.id}", follow_redirects=False).status_code == 403
    assert cb.get(f"/admin/users/{world['other_user_id']}").status_code == 200
    assert ca.get(f"/admin/users/{world['other_user_id']}", follow_redirects=False).status_code == 403
    assert ca.get("/admin/users/not-a-uuid", follow_redirects=False).status_code == 404


ENROLMENT_ROUTES = {("GET", "/admin/totp/setup"), ("POST", "/admin/totp/setup"), ("POST", "/admin/logout")}


def test_session_policy_routes_are_exactly_logout_and_the_enrolment_pages():
    session_routes = {(m, p) for m, p, calls in ROUTES if policy_of(m, p, calls) == "session"}
    assert session_routes == ENROLMENT_ROUTES


@pytest.fixture
def unenrolled(app, chair, monkeypatch):
    """name -> (client, csrf) for admins without TOTP while BALANCE_TOTP_REQUIRED is true."""
    from tests.conftest import reload_settings
    monkeypatch.setenv("BALANCE_TOTP_REQUIRED", "true")
    reload_settings()
    out = {}
    for name, role, chairs in (("head", "global", ()), ("group", "chair", [chair])):
        admin_id, _ = make_real_admin(role=role, chairs=chairs, username=name, totp=False)
        c = new_client(app)
        out[name] = (c, login_as(c, admin_id))
    return out


@pytest.mark.parametrize("method,path,calls", ROUTES, ids=IDS)
def test_unenrolled_admins_are_confined_to_the_enrolment_pages(method, path, calls, world, unenrolled):
    """With BALANCE_TOTP_REQUIRED every /admin route except login, logout and the enrolment pages
    redirects an admin without TOTP to the one-time enrolment (head admin and group admin alike)."""
    policy = policy_of(method, path, calls)
    if policy == "public" or (method, path) == ("POST", "/admin/logout"):
        return
    for name, (client, csrf) in unenrolled.items():
        r = call(client, method, path, world, csrf=csrf)
        if policy == "session":  # the enrolment page itself
            if method == "GET":
                assert r.status_code == 200, name
            else:
                assert r.status_code == 401, name  # wrong code: the page is shown again
        else:
            assert r.status_code == 303 and r.headers["location"] == "/admin/totp/setup", (name, r.status_code)


def test_enrolled_admins_are_not_redirected(world, principals, monkeypatch):
    from tests.conftest import reload_settings
    monkeypatch.setenv("BALANCE_TOTP_REQUIRED", "true")
    reload_settings()
    for name in ("global", "in_scope"):
        client, _ = principals[name]
        assert client.get("/admin", follow_redirects=False).status_code == 200  # make_real_admin enrols TOTP

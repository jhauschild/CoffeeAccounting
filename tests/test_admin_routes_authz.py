"""Authorization of EVERY /admin route: anonymous, normal-user session, out-of-scope chair admin,
in-scope chair admin and global admin. The route list comes from the routers (and is cross-checked
against the OpenAPI paths of the real app), so a new route without a policy fails this test."""

from __future__ import annotations

import pytest

from app.web import admin_deps as ad
from app.web import admin_login, admin_manage, admin_users
from tests import factories
from tests.admin_support import fast_hasher, login_as, make_real_admin, new_client  # noqa: F401

PUBLIC = {("GET", "/admin/login"), ("POST", "/admin/login")}


def _calls(dependant):
    yield dependant.call
    for sub in dependant.dependencies:
        yield from _calls(sub)


def collect_routes():
    found = []
    for module in (admin_login, admin_users, admin_manage):
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
    elif ad.pending_admin in calls or ad.live_admin_session in calls:
        policy = "session"
    else:
        policy = None
    return policy


ROUTES = collect_routes()
IDS = [f"{m} {p}" for m, p, _ in ROUTES]

POST_DATA = {
    "/admin/logout": {},
    "/admin/totp": {"code": "000000"},
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
}


def test_every_admin_route_has_a_policy_and_csrf_on_posts():
    assert len(ROUTES) >= 30
    for method, path, calls in ROUTES:
        assert policy_of(method, path, calls) is not None, f"{method} {path} has no authorization dependency"
        if method == "POST" and (method, path) not in PUBLIC:
            assert ad.require_admin_csrf in calls, f"{method} {path} lacks the CSRF dependency"
            assert path in POST_DATA, f"add form data for {path} to POST_DATA"
        if method == "POST" and (method, path) in PUBLIC:
            assert ad.verify_login_csrf in calls


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
    ids = {"user_id": user.id, "user2_id": user2.id, "event_id": event.id, "chair_id": chair.id,
           "other_chair_id": other_chair.id, "other_user_id": other_user.id}
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
        return  # login/second-factor/logout routes are covered by the login tests
    allowed = {"admin": {"global", "in_scope", "out_of_scope"}, "user": {"global", "in_scope"},
               "global": {"global"}, "global-user": {"global"}}[policy]
    for name in ("out_of_scope", "in_scope", "global"):  # the mutating principals last
        client, csrf = principals[name]
        r = call(client, method, path, world, csrf=csrf)
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

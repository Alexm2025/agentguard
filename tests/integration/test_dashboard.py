from __future__ import annotations

import re

import httpx

from tests.integration.conftest import ADMIN_EMAIL, ADMIN_PW, Stack
from tests.integration.test_server_api import POLICY, event


async def ui_login(stack: Stack, email: str = ADMIN_EMAIL) -> tuple[httpx.AsyncClient, str]:
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=stack.app), base_url="http://cp.test")
    r = await c.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1)  # type: ignore[union-attr]
    r = await c.post("/login", data={"email": email, "password": ADMIN_PW, "csrf_token": token})
    assert r.status_code == 303 and r.headers["location"] == "/events"
    page = await c.get("/events")
    csrf = re.search(r'"X-CSRF-Token": "([^"]+)"', page.text).group(1)  # type: ignore[union-attr]
    return c, csrf


async def test_login_requires_form_token_and_redirects(stack: Stack) -> None:
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=stack.app), base_url="http://cp.test")
    r = await c.get("/events")
    assert r.status_code == 303 and r.headers["location"] == "/login"
    r = await c.post("/login", data={"email": ADMIN_EMAIL, "password": ADMIN_PW, "csrf_token": "forged"})
    assert r.status_code == 403
    await c.get("/login")
    token = c.cookies.get("ag_login_csrf")
    r = await c.post("/login", data={"email": ADMIN_EMAIL, "password": "wrong", "csrf_token": token})
    assert r.status_code == 200 and "Invalid email or password" in r.text


async def test_pages_render_with_data(stack: Stack) -> None:
    ingest = await stack.key(["ingest"])
    await stack.client.post(
        "/api/v1/events",
        json={"events": [event("evt_ui"), event("evt_ui2", "ALLOW")]},
        headers={"x-agentguard-key": ingest},
    )
    apr = (
        await stack.client.post(
            "/api/v1/approvals",
            json={"event": event("evt_apr", "REQUIRE_APPROVAL")},
            headers={"x-agentguard-key": ingest},
        )
    ).json()
    c, csrf = await ui_login(stack)
    for path in [
        "/events",
        "/events?action=BLOCK",
        "/events/feed",
        "/events/evt_ui",
        "/approvals",
        f"/approvals/{apr['id']}",
        "/policies",
        "/policies/new",
        "/metrics",
        "/metrics?hours=168",
        "/settings",
    ]:
        r = await c.get(path)
        assert r.status_code == 200, path
        assert "<script>" not in r.text  # no inline scripts
    detail = (await c.get("/events/evt_ui")).text
    assert "send_email.to derived from read_web(url=https://e.io)" in detail
    assert "AKIAIOSFODNN7EXAMPLE" not in detail
    assert (await c.get("/events/does-not-exist")).status_code == 404

    # resolve approval through HTMX (CSRF header)
    r = await c.post(
        f"/approvals/{apr['id']}/resolve",
        data={"decision": "approve"},
        headers={"hx-request": "true", "x-csrf-token": csrf},
    )
    assert r.status_code == 200 and "approved" in r.text and "<html" not in r.text
    # without CSRF -> rejected
    r = await c.post(f"/approvals/{apr['id']}/resolve", data={"decision": "deny"})
    assert r.status_code == 403


async def test_policy_editor_and_validation(stack: Stack) -> None:
    c, csrf = await ui_login(stack)
    r = await c.post(
        "/policies-validate", data={"yaml_text": "tools: {x: {role: bad}}"}, headers={"x-csrf-token": csrf}
    )
    assert "problem" in r.text
    r = await c.post("/policies-validate", data={"yaml_text": POLICY}, headers={"x-csrf-token": csrf})
    assert "Policy is valid" in r.text
    r = await c.post(
        "/policies/new",
        data={"name": "ui-policy", "yaml_text": "rules: [{id: x, action: NOPE}]", "csrf_token": csrf},
    )
    assert r.status_code == 200 and "problem" in r.text
    r = await c.post(
        "/policies/new",
        data={"name": "ui-policy", "yaml_text": POLICY, "comment": "first", "csrf_token": csrf},
    )
    assert r.status_code == 303
    loc = r.headers["location"]
    page = await c.get(loc)
    assert "ui-policy" in page.text and "r1" in page.text
    r = await c.post(
        loc,
        data={"yaml_text": POLICY + "  read_web: {role: source}\n", "comment": "second", "csrf_token": csrf},
    )
    assert "Saved and activated revision 2" in r.text


async def test_settings_keys_and_xss_escaping(stack: Stack) -> None:
    ingest = await stack.key(["ingest"])
    xss = event("evt_xss", tool="<script>alert(1)</script>")
    await stack.client.post("/api/v1/events", json={"events": [xss]}, headers={"x-agentguard-key": ingest})
    c, csrf = await ui_login(stack)
    page = (await c.get("/events")).text
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    r = await c.post("/settings/keys", data={"name": "ui key", "scopes": ["ingest", "read"], "csrf_token": csrf})
    assert r.status_code == 200 and re.search(r"ag_live_[A-Za-z0-9]{40}", r.text)
    assert "chain verified" in r.text
    r = await c.post("/events/evt_xss/false-positive", data={"note": "fine", "csrf_token": csrf})
    assert r.status_code == 303


async def test_viewer_cannot_mutate(stack: Stack) -> None:
    await stack.add_user("v@acme.test", "viewer")
    c, csrf = await ui_login(stack, "v@acme.test")
    assert (await c.get("/policies/new")).status_code == 403
    r = await c.post("/settings/keys", data={"name": "x", "scopes": ["admin"], "csrf_token": csrf})
    assert r.status_code == 403
    r = await c.post("/logout", data={"csrf_token": csrf})
    assert r.status_code == 303 and (await c.get("/events")).status_code == 303

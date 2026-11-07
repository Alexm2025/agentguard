"""Plain-language pages: Home, Protection rules switches and adding teammates."""

from __future__ import annotations

import yaml

from agentguard.core.policy.loader import parse_policy
from tests.integration.conftest import Stack
from tests.integration.test_dashboard import ui_login
from tests.integration.test_server_api import event


async def _live_yaml(stack: Stack) -> str:
    key = await stack.key(["read", "ingest"])
    r = await stack.client.get("/api/v1/policies/active", headers={"x-agentguard-key": key})
    assert r.status_code == 200
    return str(r.json()["yaml"])


async def test_home_shows_plain_status(stack: Stack) -> None:
    c, _ = await ui_login(stack)
    page = (await c.get("/home")).text
    assert "Let's protect your first agent" in page
    ingest = await stack.key(["ingest"])
    await stack.client.post(
        "/api/v1/approvals", json={"event": event("evt_h", "REQUIRE_APPROVAL")}, headers={"x-agentguard-key": ingest}
    )
    page = (await c.get("/home")).text
    assert "1 action waiting for your OK" in page


async def test_activity_uses_plain_words(stack: Stack) -> None:
    ingest = await stack.key(["ingest"])
    await stack.client.post("/api/v1/events", json={"events": [event("evt_pw")]}, headers={"x-agentguard-key": ingest})
    c, _ = await ui_login(stack)
    feed = (await c.get("/events/feed")).text
    assert "Stopped your agent from trying to send an email" in feed
    detail = (await c.get("/events/evt_pw")).text
    assert "AgentGuard stopped it. Nothing was sent or changed." in detail
    assert "Technical details" in detail


async def test_rules_switches_write_a_valid_policy(stack: Stack) -> None:
    c, csrf = await ui_login(stack)
    page = (await c.get("/rules")).text
    assert page.count("checked") >= 5  # every protection on by default
    form = {
        "csrf_token": csrf,
        "on_addresses": "1",
        "on_hidden": "1",
        "on_risky": "1",
        "on_links": "1",
        "fail_mode": "open",
        "wait": "3600",
    }
    r = await c.post("/rules", data=form)
    assert r.status_code == 303 and r.headers["location"] == "/rules?saved=1"
    text = await _live_yaml(stack)
    data = yaml.safe_load(text)
    assert data["extends"] == "default" and data["settings"]["fail_mode"] == "open"
    assert data["settings"]["approvals"]["timeout_seconds"] == 3600
    pol = parse_policy(text)
    rules = {r.id: r for r in pol.rules}
    assert rules["secrets-to-sink"].enabled is False and rules["secrets-in-url"].enabled is False
    assert rules["tainted-destination"].enabled is True  # inherited from the default
    page = (await c.get("/rules?saved=1")).text
    assert "Saved." in page

    # Turning everything back on removes the overrides again.
    form.update({"on_secrets": "1", "fail_mode": "closed", "wait": "300"})
    await c.post("/rules", data=form)
    data = yaml.safe_load(await _live_yaml(stack))
    assert not data.get("rules") and data["settings"]["fail_mode"] == "closed"


async def test_rules_respect_a_standalone_policy(stack: Stack) -> None:
    from agentguard.core.policy.loader import default_policy_text

    c, csrf = await ui_login(stack)
    standalone = default_policy_text().replace("name: default", "name: mine", 1)
    r = await c.post("/policies/new", data={"name": "mine", "yaml_text": standalone, "csrf_token": csrf})
    assert r.status_code == 303
    await c.post(
        "/rules",
        data={
            "csrf_token": csrf,
            "on_addresses": "1",
            "on_secrets": "1",
            "on_hidden": "1",
            "on_risky": "1",
            "fail_mode": "closed",
            "wait": "300",
        },
    )
    pol = parse_policy(await _live_yaml(stack))
    rules = {r.id: r for r in pol.rules}
    assert pol.name == "mine"
    assert rules["exfil-via-url-params"].enabled is False
    assert rules["secrets-to-sink"].enabled is True


async def test_viewer_cannot_change_rules_or_team(stack: Stack) -> None:
    await stack.add_user("view@acme.test", "viewer")
    c, csrf = await ui_login(stack, "view@acme.test")
    assert "Only admins can change these" in (await c.get("/rules")).text
    assert (await c.post("/rules", data={"csrf_token": csrf})).status_code == 403
    r = await c.post(
        "/settings/members",
        data={"csrf_token": csrf, "email": "x@acme.test", "role": "admin", "password": "a-long-temporary-pw"},
    )
    assert r.status_code == 403


async def test_admin_adds_teammate_who_can_sign_in(stack: Stack) -> None:
    c, csrf = await ui_login(stack)
    r = await c.post(
        "/settings/members",
        data={"csrf_token": csrf, "email": "Sam@Acme.test", "name": "Sam", "role": "analyst", "password": "short"},
    )
    assert r.status_code == 422
    r = await c.post(
        "/settings/members",
        data={
            "csrf_token": csrf,
            "email": "Sam@Acme.test",
            "name": "Sam",
            "role": "analyst",
            "password": "temporary-password-1",
        },
    )
    assert r.status_code == 303 and r.headers["location"] == "/settings?added=1"
    assert "sam@acme.test" in (await c.get("/settings?added=1")).text
    import re

    import httpx

    s = httpx.AsyncClient(transport=httpx.ASGITransport(app=stack.app), base_url="http://cp.test")
    token = re.search(r'name="csrf_token" value="([^"]+)"', (await s.get("/login")).text).group(1)  # type: ignore[union-attr]
    r = await s.post("/login", data={"email": "sam@acme.test", "password": "temporary-password-1", "csrf_token": token})
    assert r.status_code == 303 and r.headers["location"] == "/home"


async def test_guide_is_public_and_inside_the_console(stack: Stack) -> None:
    import httpx

    anon = httpx.AsyncClient(transport=httpx.ASGITransport(app=stack.app), base_url="http://cp.test")
    r = await anon.get("/guide")
    assert r.status_code == 200 and "What AgentGuard is" in r.text and 'class="sidebar"' not in r.text
    c, _ = await ui_login(stack)
    r = await c.get("/guide")
    assert r.status_code == 200 and "What AgentGuard is" in r.text and 'class="sidebar"' in r.text
    assert 'href="/guide"' in (await c.get("/home")).text


async def test_terms_and_privacy_pages(stack: Stack) -> None:
    import httpx

    anon = httpx.AsyncClient(transport=httpx.ASGITransport(app=stack.app), base_url="http://cp.test")
    terms = await anon.get("/terms")
    privacy = await anon.get("/privacy")
    assert terms.status_code == 200 and "Terms of service" in terms.text
    assert privacy.status_code == 200 and "Privacy policy" in privacy.text
    days = stack.app.state.settings.event_retention_days
    assert f"{days} days" in privacy.text and "no advertising" in privacy.text


async def test_prune_removes_old_events_and_expired_sessions(stack: Stack) -> None:
    from datetime import timedelta

    from sqlalchemy import func, select

    from agentguard.server.models import Event, WebSession, utcnow
    from agentguard.server.services import prune_events

    ingest = await stack.key(["ingest"])
    await stack.client.post("/api/v1/events", json={"events": [event("evt_old")]}, headers={"x-agentguard-key": ingest})
    await ui_login(stack)  # creates a sign-in session
    db = stack.app.state.database
    async with db.sessionmaker() as s:
        ev = await s.get(Event, "evt_old")
        assert ev is not None
        ev.received_at = utcnow() - timedelta(days=400)
        for ws in (await s.execute(select(WebSession))).scalars():
            ws.expires_at = utcnow() - timedelta(hours=1)
        await s.commit()
        assert await prune_events(s, 90) == 1
        assert (await s.execute(select(func.count()).select_from(WebSession))).scalar() == 0

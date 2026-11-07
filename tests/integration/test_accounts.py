"""Self-service accounts: landing, sign-up, email verification, password reset, account, onboarding."""

from __future__ import annotations

import re

import httpx
import pytest
from sqlalchemy import select

from agentguard.server import mailer
from agentguard.server.models import Membership, Organization, User
from tests.integration.conftest import ADMIN_EMAIL, ADMIN_PW, Stack

PW = "a-very-long-password-123"


def form_token(html: str) -> str:
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)  # type: ignore[union-attr]


def browser(stack: Stack) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=stack.app), base_url="http://cp.test")


async def signup(
    c: httpx.AsyncClient, email: str = "new@startup.test", org: str = "Startup Inc", password: str = PW
) -> httpx.Response:
    page = await c.get("/signup")
    return await c.post(
        "/signup",
        data={
            "name": "Nia",
            "email": email,
            "organization": org,
            "password": password,
            "csrf_token": form_token(page.text),
        },
    )


async def test_landing_and_signup_disabled_by_default(stack: Stack) -> None:
    c = browser(stack)
    r = await c.get("/")
    assert r.status_code == 200 and "before your agent acts" in r.text and 'href="/signup"' not in r.text
    assert (await c.get("/signup")).status_code == 404


async def test_signup_creates_isolated_org_and_onboarding(stack: Stack) -> None:
    stack.settings.allow_signup = True
    c = browser(stack)
    assert 'href="/signup"' in (await c.get("/")).text
    r = await signup(c)
    assert r.status_code == 303 and r.headers["location"] == "/welcome"
    welcome = await c.get("/welcome")
    assert (
        welcome.status_code == 200
        and "Protect your AI agent in 3 steps" in welcome.text
        and "Startup Inc" in welcome.text
    )
    # logged-in visitors skip the landing page
    assert (await c.get("/")).headers["location"] == "/home"
    async with stack.db.sessionmaker() as s:
        user = (await s.execute(select(User).where(User.email == "new@startup.test"))).scalar_one()
        mem = (await s.execute(select(Membership).where(Membership.user_id == user.id))).scalar_one()
        org = await s.get(Organization, mem.org_id)
    assert (
        mem.role == "admin"
        and org is not None
        and org.slug.startswith("startup-inc")
        and user.email_verified_at is not None
    )

    csrf = re.search(r'"X-CSRF-Token": "([^"]+)"', welcome.text).group(1)  # type: ignore[union-attr]
    r = await c.post("/welcome/key", data={"csrf_token": csrf})
    key = re.search(r"ag_live_[A-Za-z0-9]{40}", r.text).group(0)  # type: ignore[union-attr]
    assert key in r.text and "Copy this key now" in r.text
    r = await c.post("/welcome/sample", data={"csrf_token": csrf})
    assert r.status_code == 303
    events = (await c.get("/api/v1/events?type=tool_call", headers={"x-csrf-token": csrf})).json()["events"]
    assert {e["action"] for e in events} >= {"BLOCK", "ALLOW"}
    # the new org is isolated from the bootstrap org
    admin = await stack.login()
    assert (await admin.get("/api/v1/events")).json()["events"] == []
    # duplicate email and weak password are rejected
    c2 = browser(stack)
    assert "already exists" in (await signup(c2)).text
    assert "at least 12" in (await signup(c2, email="x@startup.test", password="short")).text


async def test_signup_with_email_verification_and_password_reset(stack: Stack, monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[tuple[str, str, str]] = []

    async def fake_send(settings, to, subject, text):  # type: ignore[no-untyped-def]
        sent.append((to, subject, text))
        return True

    monkeypatch.setattr(mailer, "send", fake_send)
    stack.settings.allow_signup = True
    stack.settings.smtp_url = "smtp://mail.test:587"
    c = browser(stack)
    r = await signup(c, email="v@startup.test")
    assert "Check your email" in r.text and sent[0][0] == "v@startup.test"
    # cannot sign in before verifying
    page = await c.get("/login")
    r = await c.post("/login", data={"email": "v@startup.test", "password": PW, "csrf_token": form_token(page.text)})
    assert "Confirm your email first" in r.text
    link = re.search(r"https?://\S+/verify\?token=\S+", sent[0][2]).group(0)  # type: ignore[union-attr]
    assert (await c.get("/verify?token=bogus")).status_code == 200
    r = await c.get(link.split("cp.test", 1)[1])
    assert r.status_code == 303 and r.headers["location"] == "/welcome"

    # password reset: same response for unknown addresses, one-time link
    c3 = browser(stack)
    page = await c3.get("/forgot")
    r = await c3.post("/forgot", data={"email": "nobody@startup.test", "csrf_token": form_token(page.text)})
    assert "If an account exists" in r.text and len(sent) == 1
    page = await c3.get("/forgot")
    await c3.post("/forgot", data={"email": "v@startup.test", "csrf_token": form_token(page.text)})
    reset_link = re.search(r"/reset\?token=\S+", sent[-1][2]).group(0)  # type: ignore[union-attr]
    page = await c3.get(reset_link)
    assert "Choose a new password" in page.text
    token = re.search(r'name="token" value="([^"]+)"', page.text).group(1)  # type: ignore[union-attr]
    r = await c3.post(
        "/reset", data={"token": token, "password": "another-long-password-9", "csrf_token": form_token(page.text)}
    )
    assert "Password updated" in r.text
    assert "invalid, used or expired" in (await c3.get(reset_link)).text  # single use
    page = await c3.get("/login")
    r = await c3.post(
        "/login",
        data={"email": "v@startup.test", "password": "another-long-password-9", "csrf_token": form_token(page.text)},
    )
    assert r.status_code == 303


async def test_account_password_change(stack: Stack) -> None:
    c = browser(stack)
    page = await c.get("/login")
    await c.post("/login", data={"email": ADMIN_EMAIL, "password": ADMIN_PW, "csrf_token": form_token(page.text)})
    acct = await c.get("/account")
    assert acct.status_code == 200 and ADMIN_EMAIL in acct.text
    csrf = re.search(r'"X-CSRF-Token": "([^"]+)"', acct.text).group(1)  # type: ignore[union-attr]
    r = await c.post("/account/password", data={"current": "wrong", "new": "x" * 14, "csrf_token": csrf})
    assert "incorrect" in r.text
    r = await c.post(
        "/account/password", data={"current": ADMIN_PW, "new": "brand-new-password-77", "csrf_token": csrf}
    )
    assert "Password changed" in r.text
    assert (await c.get("/events")).status_code == 200  # this session survives
    page = await browser(stack).get("/forgot")
    assert "not enabled" in page.text  # no SMTP configured


async def test_mailer_reports_failure_without_raising(stack: Stack) -> None:
    stack.settings.smtp_url = "smtp://127.0.0.1:1"
    assert await mailer.send(stack.settings, "a@b.test", "s", "t") is False
    stack.settings.smtp_url = None
    assert await mailer.send(stack.settings, "a@b.test", "s", "t") is False


async def test_signup_saves_nothing_when_the_confirmation_email_fails(
    stack: Stack, monkeypatch: pytest.MonkeyPatch
) -> None:
    outcome = {"ok": False}

    async def flaky_send(settings, to, subject, text):  # type: ignore[no-untyped-def]
        return outcome["ok"]

    monkeypatch.setattr(mailer, "send", flaky_send)
    stack.settings.allow_signup = True
    stack.settings.smtp_url = "smtp://mail.test:2525"
    c = browser(stack)
    r = await signup(c, email="retry@startup.test")
    assert "couldn&#39;t send your confirmation email" in r.text or "couldn't send your confirmation email" in r.text
    outcome["ok"] = True  # the person tries again once email works: the address is still free
    r = await signup(browser(stack), email="retry@startup.test")
    assert "Check your email" in r.text

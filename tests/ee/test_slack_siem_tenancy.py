from __future__ import annotations

import hashlib
import hmac
import json
import socket
import threading
import time
import urllib.parse
from pathlib import Path

import httpx
import pytest

pytest.importorskip("agentguard_ee")

from agentguard.core.ratelimit import MemoryRateLimiter
from agentguard.server.app import bootstrap, create_app
from agentguard.server.db import Database
from agentguard.server.security import hmac_signature
from agentguard.server.settings import ServerSettings
from agentguard_ee import siem, slack

ROOT_PW = "correct horse battery staple"


def test_slack_signature_reference_vector() -> None:
    # Example from Slack's "Verifying requests from Slack" documentation.
    secret = "8f742231b10e8888abcd99yyyzzz85a5"
    body = (
        b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar"
        b"&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com"
        b"%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c"
    )
    sig = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503"
    assert slack.verify_signature(secret, "1531420618", body, sig, now=1531420618)
    assert not slack.verify_signature(secret, "1531420618", body + b"x", sig, now=1531420618)
    assert not slack.verify_signature(secret, "1531420618", body, sig, now=1531420618 + 3600)  # replay window
    assert not slack.verify_signature(secret, "abc", body, sig)


def _sign_slack(secret: str, body: bytes) -> dict[str, str]:
    ts = str(int(time.time()))
    sig = "v0=" + hmac.new(secret.encode(), b"v0:" + ts.encode() + b":" + body, hashlib.sha256).hexdigest()
    return {
        "x-slack-request-timestamp": ts,
        "x-slack-signature": sig,
        "content-type": "application/x-www-form-urlencoded",
    }


async def make_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **env: str):  # type: ignore[no-untyped-def]
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    settings = ServerSettings(
        env="test",
        database_url=f"sqlite+aiosqlite:///{(tmp_path / 'e.db').as_posix()}",
        secret_key="y" * 48,
        bootstrap_admin_email="root@acme.test",
        bootstrap_admin_password=ROOT_PW,
        public_url="http://cp.test",
    )
    db = Database(settings.database_url)
    await db.create_all()
    await bootstrap(db, settings)
    return create_app(settings, database=db, create_schema=False, rate_limiter=MemoryRateLimiter())


async def login(app, email: str = "root@acme.test") -> httpx.AsyncClient:  # type: ignore[no-untyped-def]
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://cp.test")
    r = await c.post("/api/v1/auth/login", json={"email": email, "password": ROOT_PW})
    c.headers["x-csrf-token"] = r.json()["csrf_token"]
    return c


async def test_slack_approval_flow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "slack-signing-secret-0123456789"
    app = await make_app(
        tmp_path,
        monkeypatch,
        AGENTGUARD_SLACK_BOT_TOKEN="xoxb-test",
        AGENTGUARD_SLACK_SIGNING_SECRET=secret,
        AGENTGUARD_SLACK_CHANNEL="C123",
        AGENTGUARD_SLACK_APPROVER_IDS="UAPPROVER",
    )
    posted: list[dict] = []

    def slack_api(req: httpx.Request) -> httpx.Response:
        assert req.headers["authorization"] == "Bearer xoxb-test"
        posted.append(json.loads(req.content))
        return httpx.Response(200, json={"ok": True, "ts": "1.2"})

    async def notifier(apr, org, settings):  # type: ignore[no-untyped-def]
        await slack.notifier(
            apr,
            org,
            settings,
            cfg=app.state.slack,
            client=httpx.AsyncClient(transport=httpx.MockTransport(slack_api)),
        )

    app.state.approval_notifiers = [n for n in app.state.approval_notifiers if n is not slack.notifier] + [notifier]
    admin = await login(app)
    key = (await admin.post("/api/v1/api-keys", json={"name": "k", "scopes": ["ingest"]})).json()["key"]
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://cp.test")
    apr = (
        await c.post(
            "/api/v1/approvals",
            headers={"x-agentguard-key": key},
            json={
                "event": {
                    "id": "evt_s",
                    "type": "tool_call",
                    "tool": "wire_money",
                    "action": "REQUIRE_APPROVAL",
                    "risk": "critical",
                    "arguments": {"amount": 900},
                    "reasons": [{"message": "destructive action", "action": "REQUIRE_APPROVAL"}],
                }
            },
        )
    ).json()
    assert posted and posted[0]["channel"] == "C123"
    actions = next(b for b in posted[0]["blocks"] if b["type"] == "actions")
    assert {e["action_id"] for e in actions["elements"]} == {"approve", "deny"}

    def payload(user: str, action: str = "approve") -> bytes:
        p = {
            "type": "block_actions",
            "user": {"id": user},
            "actions": [{"action_id": action, "value": apr["id"]}],
        }
        return urllib.parse.urlencode({"payload": json.dumps(p)}).encode()

    url = "/api/v1/ee/slack/interactions"
    assert (
        await c.post(url, content=payload("UAPPROVER"), headers={**_sign_slack("wrong", payload("UAPPROVER"))})
    ).status_code == 401
    r = await c.post(url, content=payload("UINTRUDER"), headers=_sign_slack(secret, payload("UINTRUDER")))
    assert "not authorised" in r.json()["text"]
    r = await c.post(url, content=payload("UAPPROVER"), headers=_sign_slack(secret, payload("UAPPROVER")))
    assert r.json()["replace_original"] and "Approved" in json.dumps(r.json()["blocks"])
    status = (await c.get(f"/api/v1/approvals/{apr['id']}", headers={"x-agentguard-key": key})).json()
    assert (
        status["status"] == "approved" and status["resolved_by"] == "slack:UAPPROVER" and status["channel"] == "slack"
    )
    r = await c.post(
        url, content=payload("UAPPROVER", "deny"), headers=_sign_slack(secret, payload("UAPPROVER", "deny"))
    )
    assert "already approved" in r.json()["text"]


def test_cef_format_and_escaping() -> None:
    ev = {
        "id": "evt_1",
        "type": "tool_call",
        "tool": "send|email",
        "action": "BLOCK",
        "timestamp": "2026-10-26T10:00:00+00:00",
        "session_id": "s",
        "taint_chain": ["send_email.to derived from read_web(url=a=b)"],
        "reasons": [{"message": "x\ny"}],
        "source": "sdk",
    }
    cef = siem.to_cef("org_1", ev)
    assert cef.startswith("CEF:0|AgentGuard|AgentGuard|")
    assert "send\\|email" in cef and "|8|" in cef and "url\\=a\\=b" in cef and "x\\ny" in cef and "act=BLOCK" in cef
    frame = siem.to_syslog(cef, 8).decode()
    assert frame.startswith("<104>1 ") and "agentguard" in frame


async def test_syslog_tcp_and_udp_and_webhook() -> None:
    received: list[bytes] = []
    tcp = socket.socket()
    tcp.bind(("127.0.0.1", 0))
    tcp.listen(1)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(5)

    def serve() -> None:
        conn, _ = tcp.accept()
        with conn:
            data = b""
            while chunk := conn.recv(65536):
                data += chunk
            received.append(data)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    ev = [
        {"id": "e1", "type": "tool_call", "tool": "x", "action": "BLOCK"},
        {"id": "e2", "type": "tool_call", "tool": "y", "action": "ALLOW"},
    ]
    await siem.SyslogForwarder(f"tcp://127.0.0.1:{tcp.getsockname()[1]}", min_action="BLOCK")("org", ev)
    t.join(5)
    assert received and received[0].count(b"CEF:0") == 1 and received[0].split(b" ", 1)[0].isdigit()
    await siem.SyslogForwarder(f"udp://127.0.0.1:{udp.getsockname()[1]}")("org", ev)
    assert b"CEF:0" in udp.recv(65536)
    with pytest.raises(ValueError, match="syslog URL"):
        siem.SyslogForwarder("http://x")

    seen: list[httpx.Request] = []

    def hook(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(204)

    fwd = siem.WebhookForwarder(
        "https://siem.example/in", "whsec", client=httpx.AsyncClient(transport=httpx.MockTransport(hook))
    )
    await fwd("org", ev)
    req = seen[0]
    assert req.headers["x-agentguard-signature"] == hmac_signature(
        "whsec", req.content, req.headers["x-agentguard-timestamp"]
    )
    with pytest.raises(ValueError, match="https"):
        siem.WebhookForwarder("http://siem.example/in", "s")


async def test_multitenancy_org_admin_and_switch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = await make_app(tmp_path, monkeypatch, AGENTGUARD_PLATFORM_ADMINS="root@acme.test")
    root = await login(app)
    r = await root.post("/api/v1/ee/orgs", json={"name": "Beta", "slug": "beta", "admin_email": "root@acme.test"})
    assert r.status_code == 201
    beta = r.json()["id"]
    assert (
        await root.post("/api/v1/ee/orgs", json={"name": "Beta", "slug": "beta", "admin_email": "x@y.z"})
    ).status_code == 409
    orgs = (await root.get("/api/v1/ee/orgs/mine")).json()
    assert {o["slug"] for o in orgs} == {"default", "beta"}
    r = await root.post("/api/v1/ee/orgs/switch", json={"org_id": beta})
    root.headers["x-csrf-token"] = r.json()["csrf_token"]
    assert (await root.get("/api/v1/auth/me")).json()["org_id"] == beta
    assert (await root.post("/api/v1/ee/orgs/switch", json={"org_id": "org_nope"})).status_code == 404
    monkeypatch.setenv("AGENTGUARD_PLATFORM_ADMINS", "")
    assert (
        await root.post("/api/v1/ee/orgs", json={"name": "C", "slug": "c", "admin_email": "a@b.c"})
    ).status_code == 403
    assert (await root.get("/healthz")).status_code == 200
    page = await root.get("/login")
    assert "enterprise edition" in page.text

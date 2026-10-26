from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select, update

from agentguard.server.models import Approval, AuditLog
from agentguard.server.security import sign
from tests.integration.conftest import ADMIN_PW, Stack

POLICY = "tools:\n  send_email: { role: sink, risk: high }\n"


def event(eid: str = "evt_1", action: str = "BLOCK", **kw: object) -> dict:
    return {
        "id": eid,
        "type": "tool_call",
        "tool": "send_email",
        "action": action,
        "risk": "high",
        "latency_ms": 1.5,
        "timestamp": "2026-10-26T10:00:00+00:00",
        "session_id": "s1",
        "arguments": {"to": "x@evil.io", "k": "AKIAIOSFODNN7EXAMPLE"},
        "reasons": [{"code": "RULE", "message": "tainted", "rule_id": "r", "action": "BLOCK"}],
        "taint_chain": ["send_email.to derived from read_web(url=https://e.io)"],
        **kw,
    }


async def test_login_session_and_csrf(stack: Stack) -> None:
    c = stack.client
    assert (
        await c.post("/api/v1/auth/login", json={"email": "admin@acme.test", "password": "nope"})
    ).status_code == 401
    assert (
        await c.post("/api/v1/auth/login", json={"email": "nobody@acme.test", "password": "nope"})
    ).status_code == 401
    assert (await c.get("/api/v1/auth/me")).status_code == 401
    admin = await stack.login()
    me = (await admin.get("/api/v1/auth/me")).json()
    assert me["role"] == "admin" and "policies:write" in me["permissions"]
    cookie = admin.cookies.get("ag_session")
    assert cookie
    # Cookie without CSRF token is rejected for state-changing requests.
    del admin.headers["x-csrf-token"]
    r = await admin.post("/api/v1/projects", json={"name": "P", "slug": "p"})
    assert r.status_code == 403 and "CSRF" in r.text
    admin.headers["x-csrf-token"] = "wrong"
    assert (await admin.post("/api/v1/projects", json={"name": "P", "slug": "p"})).status_code == 403
    admin.headers["x-csrf-token"] = me["csrf_token"]
    assert (await admin.post("/api/v1/projects", json={"name": "P", "slug": "p"})).status_code == 201
    assert (await admin.post("/api/v1/auth/logout")).status_code == 200
    assert (await admin.get("/api/v1/auth/me")).status_code == 401


async def test_login_rate_limited(stack: Stack) -> None:
    for _ in range(stack.settings.login_rate_limit):
        await stack.client.post("/api/v1/auth/login", json={"email": "admin@acme.test", "password": "bad"})
    r = await stack.client.post("/api/v1/auth/login", json={"email": "admin@acme.test", "password": ADMIN_PW})
    assert r.status_code == 429


async def test_api_keys_scopes_and_ingest(stack: Stack) -> None:
    admin = await stack.login()
    ingest = await stack.key(["ingest"], admin)
    read = await stack.key(["read"], admin)
    c = stack.client
    r = await c.post(
        "/api/v1/events",
        json={"events": [event(), event("evt_2", "ALLOW"), {"no": "id"}]},
        headers={"x-agentguard-key": ingest},
    )
    assert r.status_code == 202 and r.json()["accepted"] == 2
    # ingest keys cannot read events; read keys can
    assert (await c.get("/api/v1/events", headers={"x-agentguard-key": ingest})).status_code == 403
    evs = (await c.get("/api/v1/events?action=BLOCK", headers={"authorization": f"Bearer {read}"})).json()["events"]
    assert [e["id"] for e in evs] == ["evt_1"]
    assert "AKIAIOSFODNN7EXAMPLE" not in str(evs)  # scrubbed server-side
    detail = (await c.get("/api/v1/events/evt_1", headers={"x-agentguard-key": read})).json()
    assert detail["event"]["taint_chain"]
    assert [e["id"] for e in detail["session_events"]] == ["evt_2"]
    assert (await c.get("/api/v1/events", headers={"x-agentguard-key": "ag_live_bogus"})).status_code == 401
    # revoke
    keys = (await admin.get("/api/v1/api-keys")).json()
    assert all("key_hash" not in k and "key" not in k for k in keys)
    await admin.delete(f"/api/v1/api-keys/{keys[0]['id']}")
    assert (await c.get("/api/v1/events", headers={"x-agentguard-key": read})).status_code == 401
    assert (await admin.post("/api/v1/api-keys", json={"name": "x", "scopes": ["root"]})).status_code == 422


async def test_rbac_roles(stack: Stack) -> None:
    await stack.add_user("viewer@acme.test", "viewer")
    await stack.add_user("analyst@acme.test", "analyst")
    viewer = await stack.login("viewer@acme.test")
    analyst = await stack.login("analyst@acme.test")
    assert (await viewer.get("/api/v1/events")).status_code == 200
    assert (await viewer.post("/api/v1/policies", json={"name": "p", "yaml": POLICY})).status_code == 403
    assert (await viewer.get("/api/v1/api-keys")).status_code == 403
    assert (await analyst.get("/api/v1/audit")).status_code == 403
    ingest = await stack.key(["ingest"])
    apr = (
        await stack.client.post(
            "/api/v1/approvals",
            json={"event": event("evt_a", "REQUIRE_APPROVAL")},
            headers={"x-agentguard-key": ingest},
        )
    ).json()
    assert (
        await viewer.post(f"/api/v1/approvals/{apr['id']}/resolve", json={"decision": "approve"})
    ).status_code == 403
    r = await analyst.post(f"/api/v1/approvals/{apr['id']}/resolve", json={"decision": "approve", "note": "ok"})
    assert (
        r.status_code == 200
        and r.json()["status"] == "approved"
        and r.json()["resolved_by"] == "user:analyst@acme.test"
    )
    assert (await analyst.post(f"/api/v1/approvals/{apr['id']}/resolve", json={"decision": "deny"})).status_code == 409


async def test_tenant_isolation(stack: Stack) -> None:
    ingest_a = await stack.key(["ingest", "read"])
    await stack.client.post(
        "/api/v1/events", json={"events": [event("evt_secret")]}, headers={"x-agentguard-key": ingest_a}
    )
    apr = (
        await stack.client.post(
            "/api/v1/approvals",
            json={"event": event("evt_q", "REQUIRE_APPROVAL")},
            headers={"x-agentguard-key": ingest_a},
        )
    ).json()
    await stack.add_user("eve@other.test", "admin", org_slug="other")
    eve = await stack.login("eve@other.test")
    assert (await eve.get("/api/v1/events/evt_secret")).status_code == 404
    assert (await eve.get("/api/v1/events")).json()["events"] == []
    assert (await eve.post(f"/api/v1/approvals/{apr['id']}/resolve", json={"decision": "approve"})).status_code == 404
    key_b = await stack.key(["ingest"], eve)
    # Org B cannot overwrite org A's event by reusing its id, nor spoof tenant_id in the payload.
    await stack.client.post(
        "/api/v1/events",
        json={"events": [event("evt_secret", "ALLOW"), {**event("evt_b"), "tenant_id": "org_A"}]},
        headers={"x-agentguard-key": key_b},
    )
    a_view = (await stack.client.get("/api/v1/events/evt_secret", headers={"x-agentguard-key": ingest_a})).json()
    assert a_view["event"]["action"] == "BLOCK"
    b_events = (await eve.get("/api/v1/events")).json()["events"]
    assert [e["id"] for e in b_events] == ["evt_b"] and b_events[0]["tenant_id"] != "org_A"


async def test_policies_lifecycle(stack: Stack) -> None:
    admin = await stack.login()
    r = await admin.post("/api/v1/policies", json={"name": "main", "yaml": "tools:\n  x: {role: nope}\n"})
    assert r.status_code == 422 and "role" in r.text
    r = await admin.post("/api/v1/policies", json={"name": "main", "yaml": POLICY})
    assert r.status_code == 201 and r.json()["active_revision"] == 1
    pid = r.json()["id"]
    assert (await admin.post("/api/v1/policies", json={"name": "main", "yaml": POLICY})).status_code == 409
    r = await admin.post(
        f"/api/v1/policies/{pid}/versions",
        json={"yaml": POLICY + "  read_web: {role: source}\n", "comment": "add read_web"},
    )
    assert r.json()["revision"] == 2
    ingest = await stack.key(["ingest"], admin)
    active = (await stack.client.get("/api/v1/policies/active", headers={"x-agentguard-key": ingest})).json()
    assert active["revision"] == 2 and "read_web" in active["yaml"]
    await admin.post(f"/api/v1/policies/{pid}/activate/1")
    active = (await stack.client.get("/api/v1/policies/active", headers={"x-agentguard-key": ingest})).json()
    assert active["revision"] == 1
    assert (await admin.post(f"/api/v1/policies/{pid}/activate/9")).status_code == 404
    v = (await admin.post("/api/v1/policies/validate", json={"yaml": "rules: [{id: a, action: NOPE}]"})).json()
    assert not v["valid"] and v["errors"]
    detail = (await admin.get(f"/api/v1/policies/{pid}")).json()
    assert [x["revision"] for x in detail["versions"]] == [2, 1]


async def test_approvals_webhook_and_expiry(stack: Stack, monkeypatch: pytest.MonkeyPatch) -> None:
    admin = await stack.login()
    sent: list[dict] = []

    async def fake_notifier(apr, org, settings):  # type: ignore[no-untyped-def]
        from agentguard.server.services import approval_links

        sent.append(approval_links(apr, settings))

    stack.app.state.approval_notifiers.append(fake_notifier)  # type: ignore[attr-defined]
    r = await admin.patch("/api/v1/org/settings", json={"approval_webhook_url": "https://hooks.example/ag"})
    assert r.status_code == 422
    ingest = await stack.key(["ingest"], admin)
    apr = (
        await stack.client.post(
            "/api/v1/approvals",
            json={"event": event("evt_w", "REQUIRE_APPROVAL"), "timeout_seconds": 60},
            headers={"x-agentguard-key": ingest},
        )
    ).json()
    assert apr["status"] == "pending" and "AKIA" not in str(apr)
    status = (await stack.client.get(f"/api/v1/approvals/{apr['id']}", headers={"x-agentguard-key": ingest})).json()
    assert status["status"] == "pending"
    links = sent[0]
    assert (
        await stack.client.post(f"/api/v1/approvals/{apr['id']}/webhook-resolve", json={"token": "bad.sig"})
    ).status_code == 401
    r = await stack.client.post(
        f"/api/v1/approvals/{apr['id']}/webhook-resolve",
        json={"token": links["deny_token"], "actor": "oncall"},
    )
    assert r.json()["status"] == "denied" and r.json()["channel"] == "webhook"
    # token for a different approval is rejected
    other = sign({"apr": "apr_other", "org": "x", "d": "approve"}, stack.settings.secret_key, 60)
    assert (
        await stack.client.post(f"/api/v1/approvals/{apr['id']}/webhook-resolve", json={"token": other})
    ).status_code == 401
    # expiry
    apr2 = (
        await stack.client.post(
            "/api/v1/approvals",
            json={"event": event("evt_x", "REQUIRE_APPROVAL")},
            headers={"x-agentguard-key": ingest},
        )
    ).json()
    async with stack.db.sessionmaker() as s:
        row = await s.get(Approval, apr2["id"])
        row.expires_at = row.expires_at - timedelta(days=2)
        await s.commit()
    assert (await stack.client.get(f"/api/v1/approvals/{apr2['id']}", headers={"x-agentguard-key": ingest})).json()[
        "status"
    ] == "expired"
    assert (
        await admin.post(f"/api/v1/approvals/{apr2['id']}/resolve", json={"decision": "approve"})
    ).status_code == 409
    pending = (await admin.get("/api/v1/approvals?status=expired")).json()
    assert [a["id"] for a in pending] == [apr2["id"]]


async def test_audit_chain_tamper_detection(stack: Stack) -> None:
    admin = await stack.login()
    await admin.post("/api/v1/projects", json={"name": "A", "slug": "a"})
    await stack.key(["ingest"], admin)
    v = (await admin.get("/api/v1/audit/verify")).json()
    assert v["valid"] and v["entries"] >= 4
    export = (await admin.get("/api/v1/audit/export")).json()
    assert export["verification"]["valid"] and export["entries"][0]["prev_hash"] == "0" * 64
    async with stack.db.sessionmaker() as s:
        await s.execute(update(AuditLog).where(AuditLog.seq == 2).values(details={"forged": True}))
        await s.commit()
    v = (await admin.get("/api/v1/audit/verify")).json()
    assert not v["valid"] and v["broken_at"] == 2 and v["reason"] == "entry modified"
    async with stack.db.sessionmaker() as s:
        row = (await s.execute(select(AuditLog).where(AuditLog.seq == 3))).scalar_one()
        await s.delete(row)
        await s.commit()
    v = (await admin.get("/api/v1/audit/verify")).json()
    assert not v["valid"]


async def test_metrics_and_fp(stack: Stack) -> None:
    admin = await stack.login()
    ingest = await stack.key(["ingest"], admin)
    from agentguard.core.events import now_iso

    evs = [event(f"e{i}", "BLOCK" if i % 2 else "ALLOW", timestamp=now_iso(), latency_ms=float(i)) for i in range(10)]
    await stack.client.post("/api/v1/events", json={"events": evs}, headers={"x-agentguard-key": ingest})
    assert (await admin.post("/api/v1/events/e1/false-positive", json={"note": "legit"})).status_code == 201
    assert (await admin.post("/api/v1/events/nope/false-positive", json={})).status_code == 404
    m = (await admin.get("/api/v1/metrics/summary?hours=24")).json()
    assert m["attacks_blocked"] == 5 and m["tool_calls"] == 10 and m["false_positive_reports"] == 1
    assert m["false_positive_rate"] == 0.2 and m["latency_ms"]["p95"] == 9.0
    assert len((await admin.get("/api/v1/false-positives")).json()) == 1


async def test_members_and_last_admin(stack: Stack) -> None:
    admin = await stack.login()
    r = await admin.post(
        "/api/v1/members", json={"email": "new@acme.test", "role": "viewer", "password": "a-long-password-1"}
    )
    assert r.status_code == 201
    assert (await admin.post("/api/v1/members", json={"email": "new@acme.test", "role": "viewer"})).status_code == 409
    me = (await admin.get("/api/v1/auth/me")).json()
    assert (await admin.patch(f"/api/v1/members/{me['id']}", json={"role": "viewer"})).status_code == 409
    assert (await admin.delete(f"/api/v1/members/{me['id']}")).status_code == 409
    uid = r.json()["user_id"]
    assert (await admin.patch(f"/api/v1/members/{uid}", json={"role": "analyst"})).status_code == 200
    assert (await admin.delete(f"/api/v1/members/{uid}")).status_code == 204
    assert len((await admin.get("/api/v1/members")).json()) == 1


async def test_introspect_headers_health(stack: Stack) -> None:
    key = await stack.key(["gateway"])
    c = stack.client
    assert (await c.post("/api/v1/auth/introspect", json={"key": key})).status_code == 401
    r = await c.post("/api/v1/auth/introspect", json={"key": key}, headers={"authorization": "Bearer svc-token-123456"})
    assert r.json()["active"] and r.json()["scopes"] == ["gateway"]
    r = await c.post(
        "/api/v1/auth/introspect",
        json={"key": "ag_live_nope_nope"},
        headers={"authorization": "Bearer svc-token-123456"},
    )
    assert r.json() == {"active": False}
    h = (await c.get("/healthz")).headers
    assert "unsafe-inline" not in h["content-security-policy"] and h["x-frame-options"] == "DENY"
    assert (await c.get("/readyz")).json()["status"] == "ready"
    big = b"x" * (13 * 1024 * 1024)
    assert (await c.post("/api/v1/events", content=big, headers={"content-length": str(len(big))})).status_code == 413

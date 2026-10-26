"""SDK <-> control plane over real HTTP: policy fetch, event shipping, human approval."""

from __future__ import annotations

import os
import socket
import threading
import time
from pathlib import Path

import httpx
import pytest

from agentguard import Guard
from agentguard.client import ControlPlaneClient, ControlPlaneError, ControlPlaneSink
from agentguard.core.detectors.heuristic import HeuristicDetector
from agentguard.core.ratelimit import MemoryRateLimiter
from agentguard.server.app import create_app
from agentguard.server.settings import ServerSettings

ADMIN, PW = "admin@cp.test", "correct horse battery staple"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def server(tmp_path: Path):  # type: ignore[no-untyped-def]
    import uvicorn

    port = free_port()
    settings = ServerSettings(
        env="test",
        database_url=f"sqlite+aiosqlite:///{(tmp_path / 'cp.db').as_posix()}",
        secret_key="k" * 48,
        bootstrap_admin_email=ADMIN,
        bootstrap_admin_password=PW,
        public_url=f"http://127.0.0.1:{port}",
    )
    app = create_app(settings, rate_limiter=MemoryRateLimiter())
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    deadline = time.time() + 20
    while not srv.started and time.time() < deadline:
        time.sleep(0.05)
    base = f"http://127.0.0.1:{port}"
    admin = httpx.Client(base_url=base)
    r = admin.post("/api/v1/auth/login", json={"email": ADMIN, "password": PW})
    admin.headers["x-csrf-token"] = r.json()["csrf_token"]
    yield base, admin
    srv.should_exit = True
    t.join(timeout=10)


def make_key(admin: httpx.Client, scopes: list[str]) -> str:
    return str(admin.post("/api/v1/api-keys", json={"name": "sdk", "scopes": scopes}).json()["key"])


def test_guard_with_control_plane(server) -> None:  # type: ignore[no-untyped-def]
    base, admin = server
    admin.post(
        "/api/v1/policies",
        json={
            "name": "org",
            "yaml": "tools:\n  wire_money: { role: sink, risk: critical, action: REQUIRE_APPROVAL }\n",
        },
    )
    key = make_key(admin, ["ingest"])

    guard = Guard(control_plane_url=base, api_key=key, detectors=[HeuristicDetector()])
    assert guard.engine.policy.tool("wire_money").action is not None  # policy came from the server

    def approver_human() -> None:
        for _ in range(100):
            pending = admin.get("/api/v1/approvals?status=pending").json()
            if pending:
                admin.post(
                    f"/api/v1/approvals/{pending[0]['id']}/resolve",
                    json={"decision": "approve", "note": "verified by phone"},
                )
                return
            time.sleep(0.1)

    t = threading.Thread(target=approver_human)
    t.start()
    with guard.session(user="pay invoice 42"):
        # poll interval is 1s inside wait_for; approval arrives from the other thread
        decision = guard.check("wire_money", {"amount": 100, "iban": "GB82WEST12345698765432"})
    t.join()
    assert decision.action.value == "ALLOW" and decision.approval_id
    for sink in guard.engine.sinks:
        if isinstance(sink, ControlPlaneSink):
            sink.flush()
    events = admin.get("/api/v1/events?type=tool_call").json()["events"]
    assert any(e["tool"] == "wire_money" for e in events)
    resolved = admin.get(f"/api/v1/approvals/{decision.approval_id}").json()
    assert resolved["status"] == "approved" and resolved["resolution_note"] == "verified by phone"


def test_client_errors_and_policy_fallback(server, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    base, admin = server
    monkeypatch.delenv("AGENTGUARD_API_KEY", raising=False)
    with pytest.raises(ControlPlaneError):
        ControlPlaneClient(base)
    key = make_key(admin, ["ingest"])
    client = ControlPlaneClient(base, key)
    assert client.active_policy() is None  # no policy yet -> default policy is used
    store = client.policy_store(interval=0)
    assert store.get().name == "default"
    bad = ControlPlaneClient(base, "ag_live_invalid")
    with pytest.raises(ControlPlaneError):
        bad.post_events([{"id": "x", "type": "tool_call"}])
    assert os.environ.get("AGENTGUARD_API_KEY") is None

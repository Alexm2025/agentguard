"""OpenAI Agents SDK integration.

    from agentguard.sdk.openai_agents import guard_agent, AgentGuardRunHooks
    agent = guard_agent(agent, guard)
    await Runner.run(agent, prompt, hooks=AgentGuardRunHooks(guard))

``guard_agent`` wraps every ``FunctionTool`` (recursively through handoffs) so calls are evaluated
before they run and results are labelled. ``AgentGuardRunHooks`` rebuilds the provenance ledger
from the exact input items sent to the model on every LLM call.
"""

from __future__ import annotations

import dataclasses
import json
from typing import TYPE_CHECKING, Any

from agentguard.adapters import SeenSet, parse_arguments
from agentguard.adapters import openai_responses as responses
from agentguard.sdk._proxy import to_dict

if TYPE_CHECKING:
    from agentguard.guard import Guard


def guard_tool(tool: Any, guard: Guard) -> Any:
    from agents import FunctionTool

    if not isinstance(tool, FunctionTool) or getattr(tool, "_agentguard", False):
        return tool
    original = tool.on_invoke_tool

    async def on_invoke_tool(ctx: Any, input_json: str) -> Any:
        args = parse_arguments(input_json)
        call_id = getattr(ctx, "tool_call_id", None)
        decision = await guard.acheck(tool.name, args, call_id=call_id)
        if not decision.allowed:
            return guard._blocked(decision, guard.on_block)
        if decision.redacted_arguments is not None:
            input_json = json.dumps(decision.redacted_arguments)
        result = await original(ctx, input_json)
        return guard.record_result(tool.name, result, arguments=args, call_id=decision.call_id).content

    new = dataclasses.replace(tool, on_invoke_tool=on_invoke_tool)
    object.__setattr__(new, "_agentguard", True)
    return new


def guard_agent(agent: Any, guard: Guard, _seen: set[int] | None = None) -> Any:
    """Return a copy of ``agent`` whose function tools (and handoff agents' tools) are guarded."""
    seen = _seen if _seen is not None else set()
    if id(agent) in seen:
        return agent
    seen.add(id(agent))
    tools = [guard_tool(t, guard) for t in agent.tools]
    handoffs = [guard_agent(h, guard, seen) if hasattr(h, "tools") else h for h in agent.handoffs]
    return agent.clone(tools=tools, handoffs=handoffs)


def _hooks_base() -> type:
    from agents import RunHooks

    return RunHooks


class AgentGuardRunHooks(_hooks_base()):  # type: ignore[misc]
    """Run hooks that feed the model's actual input into the provenance ledger."""

    def __init__(self, guard: Guard) -> None:
        super().__init__()
        self.guard = guard
        self.seen = SeenSet()

    async def on_llm_start(self, context: Any, agent: Any, system_prompt: str | None, input_items: list[Any]) -> None:
        items = [to_dict(i) for i in input_items]
        responses.ingest(self.guard.engine, self.guard.context(), system_prompt, items, self.seen)

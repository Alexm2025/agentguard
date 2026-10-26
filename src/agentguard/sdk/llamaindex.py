"""LlamaIndex integration.

    from agentguard.sdk.llamaindex import guard_tools
    tools = guard_tools([FunctionTool.from_defaults(fn=send_email)], guard)
    with guard.session(user=prompt):
        response = await agent.run(prompt)

LlamaIndex does not expose the raw model input to callbacks in a stable way, so open a
``guard.session(user=...)`` with the user's request; tool results are recorded automatically.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agentguard.guard import Guard


def guard_tool(tool: Any, guard: Guard) -> Any:
    from llama_index.core.tools import FunctionTool

    meta = tool.metadata
    name = meta.name or "tool"

    def call(**kwargs: Any) -> Any:
        return tool.call(**kwargs).raw_output

    async def acall(**kwargs: Any) -> Any:
        return (await tool.acall(**kwargs)).raw_output

    call.__name__ = acall.__name__ = name
    return FunctionTool.from_defaults(
        fn=guard.wrap_tool(call, name=name),
        async_fn=guard.wrap_tool(acall, name=name),
        name=name,
        description=meta.description,
        fn_schema=meta.fn_schema,
        return_direct=meta.return_direct,
    )


def guard_tools(tools: list[Any], guard: Guard) -> list[Any]:
    return [guard_tool(t, guard) for t in tools]

"""LangChain / LangGraph integration.

    from agentguard.sdk.langchain import guard_tools, AgentGuardCallbackHandler
    tools = guard_tools([search, send_email], guard)
    llm = ChatOpenAI(callbacks=[AgentGuardCallbackHandler(guard)])

``guard_tools`` returns ``StructuredTool`` copies whose execution is policy-checked (works with
``create_react_agent``/``ToolNode`` in LangGraph and classic ``AgentExecutor``). The callback
handler rebuilds provenance from the messages sent to the chat model on every call.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agentguard.adapters import SeenSet
from agentguard.adapters import openai_chat as chat

if TYPE_CHECKING:
    from agentguard.guard import Guard


def guard_tool(tool: Any, guard: Guard) -> Any:
    from langchain_core.tools import StructuredTool

    if getattr(tool, "metadata", None) and tool.metadata.get("agentguard"):
        return tool

    def run(**kwargs: Any) -> Any:
        return tool.invoke(kwargs)

    async def arun(**kwargs: Any) -> Any:
        return await tool.ainvoke(kwargs)

    run.__name__ = arun.__name__ = tool.name
    return StructuredTool(
        name=tool.name,
        description=tool.description,
        args_schema=tool.args_schema,
        func=guard.wrap_tool(run, name=tool.name),
        coroutine=guard.wrap_tool(arun, name=tool.name),
        return_direct=getattr(tool, "return_direct", False),
        metadata={**(tool.metadata or {}), "agentguard": True},
        tags=tool.tags,
        response_format=getattr(tool, "response_format", "content"),
    )


def guard_tools(tools: list[Any], guard: Guard) -> list[Any]:
    return [guard_tool(t, guard) for t in tools]


def _base() -> type:
    from langchain_core.callbacks import BaseCallbackHandler

    return BaseCallbackHandler


class AgentGuardCallbackHandler(_base()):  # type: ignore[misc]
    """Feeds the exact chat-model input into the provenance ledger."""

    raise_error = True

    def __init__(self, guard: Guard) -> None:
        super().__init__()
        self.guard = guard
        self.seen = SeenSet()

    def on_chat_model_start(self, serialized: Any, messages: list[list[Any]], **kwargs: Any) -> None:
        from langchain_core.messages import convert_to_openai_messages

        if not messages:
            return
        dicts = convert_to_openai_messages(messages[0])
        chat.ingest_messages(self.guard.engine, self.guard.context(), dicts, self.seen)

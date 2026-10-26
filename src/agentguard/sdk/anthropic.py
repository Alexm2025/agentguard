"""Guard an ``anthropic.Anthropic`` / ``anthropic.AsyncAnthropic`` client.

    client = guard.wrap_anthropic(Anthropic())

Supports ``messages.create`` including ``stream=True`` (raw event stream). The ``messages.stream()``
helper raises :class:`AgentGuardError` instead of running unguarded.
"""

from __future__ import annotations

import inspect
from collections.abc import AsyncIterator, Iterator
from typing import TYPE_CHECKING, Any, Literal

from agentguard.adapters import SeenSet, block_notice
from agentguard.adapters import anthropic_messages as am
from agentguard.core.errors import AgentGuardError, ToolCallBlocked
from agentguard.core.types import Decision
from agentguard.sdk._proxy import Proxy, rebuild, to_dict

if TYPE_CHECKING:
    from agentguard.guard import Guard

Mode = Literal["rewrite", "raise"]


def _event_cls(name: str) -> Any:
    import anthropic.types as t

    return getattr(t, name)


class _MsgGuard:
    def __init__(self, guard: Guard, mode: Mode) -> None:
        self.guard, self.mode, self.seen = guard, mode, SeenSet()

    def prepare(self, kwargs: dict[str, Any]) -> None:
        messages = kwargs.get("messages")
        if not messages:
            return
        dicts = [to_dict(m) for m in messages]
        results = am.ingest(self.guard.engine, self.guard.context(), to_dict(kwargs.get("system")), dicts, self.seen)
        sanitized = am.sanitize_request(dicts, results)
        if sanitized is not dicts:
            kwargs["messages"] = sanitized

    def finish(self, resp: Any, decisions: dict[int, Decision]) -> Any:
        blocked = [d for d in decisions.values() if not d.allowed]
        if blocked and self.mode == "raise":
            raise ToolCallBlocked(blocked[0])
        if blocked or any(d.redacted_arguments is not None for d in decisions.values()):
            return rebuild(resp, am.rewrite_response(to_dict(resp), decisions))
        return resp

    def replacement_events(self, held: dict[int, list[Any]], decisions: dict[int, Decision]) -> list[Any]:
        """Re-emit allowed tool_use blocks; replace blocked ones with a text block at the same index."""
        out: list[Any] = []
        for idx in sorted(held):
            d = decisions.get(idx)
            if d is None or d.allowed:
                out.extend(held[idx])
                continue
            text = block_notice([d])
            out.append(
                _event_cls("RawContentBlockStartEvent").model_validate(
                    {
                        "type": "content_block_start",
                        "index": idx,
                        "content_block": {"type": "text", "text": ""},
                    }
                )
            )
            out.append(
                _event_cls("RawContentBlockDeltaEvent").model_validate(
                    {
                        "type": "content_block_delta",
                        "index": idx,
                        "delta": {"type": "text_delta", "text": text},
                    }
                )
            )
            out.append(
                _event_cls("RawContentBlockStopEvent").model_validate({"type": "content_block_stop", "index": idx})
            )
        return out

    def fix_message_delta(self, event: Any, decisions: dict[int, Decision]) -> Any:
        if decisions and all(not d.allowed for d in decisions.values()):
            data = to_dict(event)
            if (data.get("delta") or {}).get("stop_reason") == "tool_use":
                data["delta"]["stop_reason"] = "end_turn"
                return rebuild(event, data)
        return event


class _SyncStream:
    def __init__(self, g: _MsgGuard, upstream: Any) -> None:
        self.g, self.upstream = g, upstream

    def __iter__(self) -> Iterator[Any]:
        buf = am.StreamToolBuffer()
        for event in self.upstream:
            data = to_dict(event)
            etype = data.get("type", "")
            idx = buf.is_tool_event(etype, data)
            if idx is not None:
                buf.events[idx].append(event)
                continue
            if etype == "message_delta" and buf.blocks:
                decisions = {i: self.g.guard.check(c.name, c.arguments, call_id=c.call_id) for i, c in buf.tool_calls()}
                blocked = [d for d in decisions.values() if not d.allowed]
                if blocked and self.g.mode == "raise":
                    raise ToolCallBlocked(blocked[0])
                yield from self.g.replacement_events(buf.events, decisions)
                buf.events.clear()
                buf.blocks.clear()
                yield self.g.fix_message_delta(event, decisions)
                continue
            yield event

    def __enter__(self) -> _SyncStream:
        return self

    def __exit__(self, *exc: Any) -> None:
        close = getattr(self.upstream, "close", None)
        if close:
            close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.upstream, name)


class _AsyncStream:
    def __init__(self, g: _MsgGuard, upstream: Any) -> None:
        self.g, self.upstream = g, upstream

    async def __aiter__(self) -> AsyncIterator[Any]:
        buf = am.StreamToolBuffer()
        async for event in self.upstream:
            data = to_dict(event)
            etype = data.get("type", "")
            idx = buf.is_tool_event(etype, data)
            if idx is not None:
                buf.events[idx].append(event)
                continue
            if etype == "message_delta" and buf.blocks:
                decisions = {
                    i: await self.g.guard.acheck(c.name, c.arguments, call_id=c.call_id) for i, c in buf.tool_calls()
                }
                blocked = [d for d in decisions.values() if not d.allowed]
                if blocked and self.g.mode == "raise":
                    raise ToolCallBlocked(blocked[0])
                for e in self.g.replacement_events(buf.events, decisions):
                    yield e
                buf.events.clear()
                buf.blocks.clear()
                yield self.g.fix_message_delta(event, decisions)
                continue
            yield event

    async def __aenter__(self) -> _AsyncStream:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        close = getattr(self.upstream, "close", None)
        if close:
            res = close()
            if inspect.isawaitable(res):
                await res

    def __getattr__(self, name: str) -> Any:
        return getattr(self.upstream, name)


def wrap_anthropic(client: Any, guard: Guard, *, mode: Mode = "rewrite") -> Any:
    g = _MsgGuard(guard, mode)
    original = client.messages.create

    def create(*args: Any, **kwargs: Any) -> Any:
        g.prepare(kwargs)
        resp = original(*args, **kwargs)
        if inspect.isawaitable(resp):

            async def finish() -> Any:
                r = await resp
                if kwargs.get("stream"):
                    return _AsyncStream(g, r)
                decisions = {
                    i: await guard.acheck(c.name, c.arguments, call_id=c.call_id)
                    for i, c in am.response_tool_calls(to_dict(r))
                }
                return g.finish(r, decisions)

            return finish()
        if kwargs.get("stream"):
            return _SyncStream(g, resp)
        decisions = {
            i: guard.check(c.name, c.arguments, call_id=c.call_id) for i, c in am.response_tool_calls(to_dict(resp))
        }
        return g.finish(resp, decisions)

    def no_stream(*a: Any, **k: Any) -> Any:
        raise AgentGuardError(
            "messages.stream() is not supported by the AgentGuard wrapper; use messages.create(stream=True)"
        )

    messages = Proxy(client.messages, create=create, stream=no_stream)
    overrides: dict[str, Any] = {"messages": messages}
    beta = getattr(client, "beta", None)
    if beta is not None and hasattr(beta, "messages"):

        def no_beta(*a: Any, **k: Any) -> Any:
            raise AgentGuardError("client.beta.messages is not guarded by AgentGuard; use client.messages")

        overrides["beta"] = Proxy(beta, messages=Proxy(beta.messages, create=no_beta, stream=no_beta))
    return Proxy(client, **overrides)

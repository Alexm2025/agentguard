"""Guard an ``openai.OpenAI`` / ``openai.AsyncOpenAI`` client.

    client = guard.wrap_openai(OpenAI())

* Requests: the conversation is rebuilt into a provenance ledger (system/developer/user trusted,
  tool messages tainted); tool results are scanned and withheld/redacted per policy before they
  reach the model.
* Responses: every tool call is evaluated. Blocked calls are removed and replaced with an
  explanation (``mode="rewrite"``, default) or raise :class:`ToolCallBlocked` (``mode="raise"``).

Supported: ``chat.completions.create`` (incl. ``stream=True``) and ``responses.create``
(non-streaming). ``chat.completions.stream``/``parse`` helpers and ``responses.create(stream=True)``
raise :class:`AgentGuardError` rather than run unguarded.
"""

from __future__ import annotations

import inspect
from collections.abc import AsyncIterator, Iterator
from typing import TYPE_CHECKING, Any, Literal

from agentguard.adapters import SeenSet, block_notice
from agentguard.adapters import openai_chat as chat
from agentguard.adapters import openai_responses as responses
from agentguard.core.errors import AgentGuardError, ToolCallBlocked
from agentguard.core.types import Decision
from agentguard.sdk._proxy import Proxy, rebuild, to_dict

if TYPE_CHECKING:
    from agentguard.guard import Guard

Mode = Literal["rewrite", "raise"]


def _unsupported(what: str) -> Any:
    def fn(*a: Any, **k: Any) -> Any:
        raise AgentGuardError(f"{what} is not supported by the AgentGuard wrapper; use the plain create() call")

    return fn


class _ChatGuard:
    def __init__(self, guard: Guard, mode: Mode, seen: SeenSet) -> None:
        self.guard, self.mode, self.seen = guard, mode, seen

    def prepare(self, kwargs: dict[str, Any]) -> None:
        messages = kwargs.get("messages")
        if not messages:
            return
        dicts = [to_dict(m) for m in messages]
        results = chat.ingest_messages(self.guard.engine, self.guard.context(), dicts, self.seen)
        sanitized = chat.sanitize_request(dicts, results)
        if sanitized is not dicts:
            kwargs["messages"] = sanitized

    def _finish(self, data: dict[str, Any], decisions: dict[tuple[int, int], Decision]) -> dict[str, Any] | None:
        blocked = [d for d in decisions.values() if not d.allowed]
        if blocked and self.mode == "raise":
            raise ToolCallBlocked(blocked[0])
        if blocked or any(d.redacted_arguments is not None for d in decisions.values()):
            return chat.rewrite_response(data, decisions)
        return None

    def after(self, resp: Any) -> Any:
        data = to_dict(resp)
        decisions = {
            (ci, ti): self.guard.check(c.name, c.arguments, call_id=c.call_id)
            for ci, ti, c in chat.response_tool_calls(data)
        }
        new = self._finish(data, decisions)
        return rebuild(resp, new) if new is not None else resp

    async def aafter(self, resp: Any) -> Any:
        data = to_dict(resp)
        decisions = {
            (ci, ti): await self.guard.acheck(c.name, c.arguments, call_id=c.call_id)
            for ci, ti, c in chat.response_tool_calls(data)
        }
        new = self._finish(data, decisions)
        return rebuild(resp, new) if new is not None else resp

    def _stream_tail(
        self,
        held: list[Any],
        buf: chat.StreamToolBuffer,
        decisions: dict[tuple[int, int], Decision],
        final: Any,
    ) -> list[Any]:
        blocked = {k for k, d in decisions.items() if not d.allowed}
        if blocked and self.mode == "raise":
            raise ToolCallBlocked(decisions[min(blocked)])
        out = []
        for chunk in held:
            f = chat.filter_chunk(to_dict(chunk), blocked)
            if f is not None:
                out.append(rebuild(chunk, f))
        if final is not None:
            fd = to_dict(final)
            if blocked:
                notice = block_notice([decisions[k] for k in sorted(blocked)])
                for choice in fd.get("choices") or []:
                    ci = int(choice.get("index", 0))
                    if any(k[0] == ci for k in blocked):
                        choice.setdefault("delta", {})["content"] = "\n\n" + notice
                        if not any(k[0] == ci and k not in blocked for k in buf.calls):
                            choice["finish_reason"] = "stop"
            out.append(rebuild(final, fd))
        return out

    def stream(self, upstream: Any) -> _SyncStream:
        return _SyncStream(self, upstream)

    def astream(self, upstream: Any) -> _AsyncStream:
        return _AsyncStream(self, upstream)


def _finished(chunk_dict: dict[str, Any]) -> bool:
    return any(c.get("finish_reason") for c in chunk_dict.get("choices") or [])


class _SyncStream:
    def __init__(self, g: _ChatGuard, upstream: Any) -> None:
        self.g, self.upstream = g, upstream

    def __iter__(self) -> Iterator[Any]:
        buf, held = chat.StreamToolBuffer(), []
        done = False
        for chunk in self.upstream:
            d = to_dict(chunk)
            if done:
                yield chunk
                continue
            if buf.add_chunk(d) and not _finished(d):
                held.append(chunk)
                continue
            if _finished(d):
                done = True
                decisions = {k: self.g.guard.check(c.name, c.arguments, call_id=c.call_id) for k, c in buf.tool_calls()}
                yield from self.g._stream_tail(held, buf, decisions, chunk)
                held = []
                continue
            yield chunk
        if held:  # stream ended without finish_reason
            decisions = {k: self.g.guard.check(c.name, c.arguments, call_id=c.call_id) for k, c in buf.tool_calls()}
            yield from self.g._stream_tail(held, buf, decisions, None)

    def __enter__(self) -> _SyncStream:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        if hasattr(self.upstream, "close"):
            self.upstream.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.upstream, name)


class _AsyncStream:
    def __init__(self, g: _ChatGuard, upstream: Any) -> None:
        self.g, self.upstream = g, upstream

    async def __aiter__(self) -> AsyncIterator[Any]:
        buf, held = chat.StreamToolBuffer(), []
        done = False
        async for chunk in self.upstream:
            d = to_dict(chunk)
            if done:
                yield chunk
                continue
            if buf.add_chunk(d) and not _finished(d):
                held.append(chunk)
                continue
            if _finished(d):
                done = True
                decisions = {
                    k: await self.g.guard.acheck(c.name, c.arguments, call_id=c.call_id) for k, c in buf.tool_calls()
                }
                for out in self.g._stream_tail(held, buf, decisions, chunk):
                    yield out
                held = []
                continue
            yield chunk
        if held:
            decisions = {
                k: await self.g.guard.acheck(c.name, c.arguments, call_id=c.call_id) for k, c in buf.tool_calls()
            }
            for out in self.g._stream_tail(held, buf, decisions, None):
                yield out

    async def __aenter__(self) -> _AsyncStream:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def close(self) -> None:
        close = getattr(self.upstream, "close", None)
        if close is not None:
            res = close()
            if inspect.isawaitable(res):
                await res

    def __getattr__(self, name: str) -> Any:
        return getattr(self.upstream, name)


def _guard_chat_create(original: Any, g: _ChatGuard) -> Any:
    # The async client's create() is a plain function returning a coroutine, so dispatch on the
    # result rather than on inspect.iscoroutinefunction().
    def create(*args: Any, **kwargs: Any) -> Any:
        g.prepare(kwargs)
        resp = original(*args, **kwargs)
        if inspect.isawaitable(resp):

            async def finish() -> Any:
                r = await resp
                return g.astream(r) if kwargs.get("stream") else await g.aafter(r)

            return finish()
        if kwargs.get("stream"):
            return g.stream(resp)
        return g.after(resp)

    return create


def _guard_responses_create(original: Any, guard: Guard, mode: Mode, seen: SeenSet) -> Any:
    def prepare(kwargs: dict[str, Any]) -> None:
        if kwargs.get("stream"):
            raise AgentGuardError("responses.create(stream=True) is not supported by the AgentGuard wrapper yet")
        items = kwargs.get("input")
        if items is None:
            return
        dicts = items if isinstance(items, str) else [to_dict(i) for i in items]
        results = responses.ingest(guard.engine, guard.context(), kwargs.get("instructions"), dicts, seen)
        sanitized = responses.sanitize_request(dicts, results)
        if sanitized is not dicts:
            kwargs["input"] = sanitized

    def finish_sync(resp: Any, decisions: dict[int, Decision], data: dict[str, Any]) -> Any:
        blocked = [d for d in decisions.values() if not d.allowed]
        if blocked and mode == "raise":
            raise ToolCallBlocked(blocked[0])
        if blocked or any(d.redacted_arguments is not None for d in decisions.values()):
            return rebuild(resp, responses.rewrite_response(data, decisions))
        return resp

    def create(*args: Any, **kwargs: Any) -> Any:
        prepare(kwargs)
        resp = original(*args, **kwargs)
        if inspect.isawaitable(resp):

            async def finish() -> Any:
                r = await resp
                data = to_dict(r)
                decisions = {
                    i: await guard.acheck(c.name, c.arguments, call_id=c.call_id)
                    for i, c in responses.response_tool_calls(data)
                }
                return finish_sync(r, decisions, data)

            return finish()
        data = to_dict(resp)
        decisions = {
            i: guard.check(c.name, c.arguments, call_id=c.call_id) for i, c in responses.response_tool_calls(data)
        }
        return finish_sync(resp, decisions, data)

    return create


def wrap_openai(client: Any, guard: Guard, *, mode: Mode = "rewrite") -> Any:
    seen = SeenSet()
    g = _ChatGuard(guard, mode, seen)
    completions = Proxy(
        client.chat.completions,
        create=_guard_chat_create(client.chat.completions.create, g),
        stream=_unsupported("chat.completions.stream()"),
        parse=_unsupported("chat.completions.parse()"),
    )
    chat_proxy = Proxy(client.chat, completions=completions)
    overrides: dict[str, Any] = {"chat": chat_proxy}
    if hasattr(client, "responses"):
        overrides["responses"] = Proxy(
            client.responses,
            create=_guard_responses_create(client.responses.create, guard, mode, seen),
            stream=_unsupported("responses.stream()"),
            parse=_unsupported("responses.parse()"),
        )
    beta_chat = getattr(getattr(client, "beta", None), "chat", None)
    if beta_chat is not None and hasattr(beta_chat, "completions"):
        beta_completions = Proxy(
            beta_chat.completions,
            parse=_unsupported("beta.chat.completions.parse()"),
            stream=_unsupported("beta.chat.completions.stream()"),
        )
        overrides["beta"] = Proxy(client.beta, chat=Proxy(beta_chat, completions=beta_completions))
    return Proxy(client, **overrides)

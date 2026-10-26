"""OpenAI Chat Completions format (``/v1/chat/completions``)."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping, Sequence
from typing import Any

from agentguard.adapters import SeenSet, block_notice, parse_arguments
from agentguard.core.engine import Engine, GuardContext, ResultDecision
from agentguard.core.provenance import ProvenanceLedger, content_to_text
from agentguard.core.types import Action, Decision, Origin, ToolCall


def _text(content: Any) -> str:
    if isinstance(content, list):
        return "\n".join(
            p.get("text", "") if isinstance(p, Mapping) else str(p)
            for p in content
            if not isinstance(p, Mapping) or p.get("type") in (None, "text", "input_text", "output_text")
        )
    return content_to_text(content)


def ingest_messages(
    engine: Engine,
    ctx: GuardContext,
    messages: Sequence[Mapping[str, Any]],
    seen: SeenSet | None = None,
) -> dict[int, ResultDecision]:
    """Rebuild ``ctx.ledger`` from a chat message list. Returns tool-result decisions by index."""
    ctx.ledger = ProvenanceLedger(ctx.ledger.session_id)
    names: dict[str, tuple[str, dict[str, Any]]] = {}
    results: dict[int, ResultDecision] = {}
    for i, msg in enumerate(messages):
        role = msg.get("role")
        if role in ("system", "developer"):
            ctx.ledger.add(Origin.SYSTEM if role == "system" else Origin.DEVELOPER, _text(msg.get("content")))
        elif role == "user":
            ctx.ledger.add_user(_text(msg.get("content")))
        elif role == "assistant":
            text = _text(msg.get("content"))
            if text:
                ctx.ledger.add_assistant(text)
            for tc in msg.get("tool_calls") or []:
                fn = tc.get("function") or {}
                names[str(tc.get("id"))] = (str(fn.get("name", "tool")), parse_arguments(fn.get("arguments")))
            if fc := msg.get("function_call"):  # legacy
                names[f"legacy:{fc.get('name')}"] = (
                    str(fc.get("name")),
                    parse_arguments(fc.get("arguments")),
                )
        elif role in ("tool", "function"):
            call_id = str(msg.get("tool_call_id") or f"legacy:{msg.get('name')}")
            tool, args = names.get(call_id, (str(msg.get("name") or "unknown_tool"), {}))
            emit = seen.add(f"{ctx.session_id}:{call_id}") if seen else True
            results[i] = engine.inspect_result(
                ctx, tool, _text(msg.get("content")), arguments=args, call_id=call_id, emit=emit
            )
    return results


def sanitize_request(messages: list[dict[str, Any]], results: Mapping[int, ResultDecision]) -> list[dict[str, Any]]:
    """Return messages with withheld/redacted tool results replaced (copy-on-write)."""
    if not any(r.action in (Action.BLOCK, Action.REDACT) for r in results.values()):
        return messages
    out = list(messages)
    for i, r in results.items():
        if r.action in (Action.BLOCK, Action.REDACT):
            m = dict(out[i])
            m["content"] = r.content if isinstance(r.content, str) else _text(r.content)
            out[i] = m
    return out


def response_tool_calls(response: Mapping[str, Any]) -> list[tuple[int, int, ToolCall]]:
    """``(choice_index, tool_call_index, ToolCall)`` for every tool call in a completion."""
    out = []
    for ci, choice in enumerate(response.get("choices") or []):
        msg = choice.get("message") or {}
        for ti, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc.get("function") or {}
            out.append(
                (
                    ci,
                    ti,
                    ToolCall(str(fn.get("name")), parse_arguments(fn.get("arguments")), str(tc.get("id"))),
                )
            )
    return out


def rewrite_response(response: dict[str, Any], decisions: Mapping[tuple[int, int], Decision]) -> dict[str, Any]:
    """Remove blocked tool calls and explain why in the message content."""
    resp = copy.deepcopy(response)
    for ci, choice in enumerate(resp.get("choices") or []):
        msg = choice.get("message") or {}
        calls = msg.get("tool_calls") or []
        keep, blocked = [], []
        for ti, tc in enumerate(calls):
            d = decisions.get((ci, ti))
            if d is not None and not d.allowed:
                blocked.append(d)
                continue
            if d is not None and d.action is Action.REDACT and d.redacted_arguments is not None:
                keep.append({**tc, "function": {**tc["function"], "arguments": json.dumps(d.redacted_arguments)}})
            else:
                keep.append(tc)
        if not blocked and keep == calls:
            continue
        msg["tool_calls"] = keep or None
        if not keep:
            msg.pop("tool_calls", None)
            if choice.get("finish_reason") == "tool_calls":
                choice["finish_reason"] = "stop"
        if blocked:
            notice = block_notice(blocked)
            msg["content"] = f"{msg.get('content')}\n\n{notice}" if msg.get("content") else notice
        choice["message"] = msg
    return resp


class StreamToolBuffer:
    """Accumulates streamed tool-call deltas (by choice and index) until the stream finishes."""

    def __init__(self) -> None:
        self.calls: dict[tuple[int, int], dict[str, Any]] = {}

    def add_chunk(self, chunk: Mapping[str, Any]) -> bool:
        """Record tool-call deltas; return True if the chunk carried any."""
        had = False
        for choice in chunk.get("choices") or []:
            ci = int(choice.get("index", 0))
            for tc in (choice.get("delta") or {}).get("tool_calls") or []:
                had = True
                ti = int(tc.get("index", 0))
                cur = self.calls.setdefault((ci, ti), {"id": None, "name": "", "arguments": ""})
                if tc.get("id"):
                    cur["id"] = tc["id"]
                fn = tc.get("function") or {}
                if fn.get("name"):
                    cur["name"] += fn["name"]
                if fn.get("arguments"):
                    cur["arguments"] += fn["arguments"]
        return had

    def tool_calls(self) -> list[tuple[tuple[int, int], ToolCall]]:
        return [
            (k, ToolCall(v["name"], parse_arguments(v["arguments"]), v["id"] or f"call_{k[0]}_{k[1]}"))
            for k, v in sorted(self.calls.items())
        ]


def filter_chunk(chunk: dict[str, Any], blocked: set[tuple[int, int]]) -> dict[str, Any] | None:
    """Drop tool-call deltas for blocked calls. Returns None if nothing is left to send."""
    out = copy.deepcopy(chunk)
    for choice in out.get("choices") or []:
        ci = int(choice.get("index", 0))
        delta = choice.get("delta") or {}
        tcs = delta.get("tool_calls")
        if tcs:
            delta["tool_calls"] = [tc for tc in tcs if (ci, int(tc.get("index", 0))) not in blocked]
            if not delta["tool_calls"]:
                del delta["tool_calls"]
    if not any(
        (c.get("delta") or {}).get("tool_calls")
        or (c.get("delta") or {}).get("content")
        or c.get("finish_reason")
        or (c.get("delta") or {}).get("role")
        for c in out.get("choices") or []
    ) and not out.get("usage"):
        return None
    return out

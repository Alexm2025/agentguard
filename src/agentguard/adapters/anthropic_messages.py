"""Anthropic Messages format (``/v1/messages``)."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any

from agentguard.adapters import SeenSet, block_notice
from agentguard.core.engine import Engine, GuardContext, ResultDecision
from agentguard.core.provenance import ProvenanceLedger
from agentguard.core.types import Action, Decision, ToolCall


def _blocks(content: Any) -> list[Mapping[str, Any]]:
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    return [b for b in content or [] if isinstance(b, Mapping)]


def _text_of(blocks: Any) -> str:
    if isinstance(blocks, str):
        return blocks
    parts = []
    for b in _blocks(blocks):
        if b.get("type") == "text":
            parts.append(str(b.get("text", "")))
        elif b.get("type") == "document":
            src = b.get("source") or {}
            if isinstance(src.get("data"), str) and src.get("type") == "text":
                parts.append(src["data"])
    return "\n".join(parts)


def ingest(
    engine: Engine,
    ctx: GuardContext,
    system: Any,
    messages: Sequence[Mapping[str, Any]],
    seen: SeenSet | None = None,
) -> dict[tuple[int, int], ResultDecision]:
    """Rebuild ``ctx.ledger`` from a Messages request. Returns tool_result decisions keyed by
    (message index, block index)."""
    ctx.ledger = ProvenanceLedger(ctx.ledger.session_id)
    if system:
        ctx.ledger.add_system(_text_of(system))
    names: dict[str, tuple[str, dict[str, Any]]] = {}
    results: dict[tuple[int, int], ResultDecision] = {}
    for mi, msg in enumerate(messages):
        role = msg.get("role")
        for bi, block in enumerate(_blocks(msg.get("content"))):
            btype = block.get("type")
            if btype == "tool_use":
                inp = block.get("input")
                names[str(block.get("id"))] = (str(block.get("name")), inp if isinstance(inp, dict) else {})
            elif btype == "tool_result":
                call_id = str(block.get("tool_use_id"))
                tool, args = names.get(call_id, ("unknown_tool", {}))
                emit = seen.add(f"{ctx.session_id}:{call_id}") if seen else True
                results[(mi, bi)] = engine.inspect_result(
                    ctx, tool, _text_of(block.get("content")), arguments=args, call_id=call_id, emit=emit
                )
            elif btype in ("text", "document"):
                text = _text_of([block])
                if not text:
                    continue
                if role == "user":
                    ctx.ledger.add_user(text)
                else:
                    ctx.ledger.add_assistant(text)
    return results


def sanitize_request(
    messages: list[dict[str, Any]], results: Mapping[tuple[int, int], ResultDecision]
) -> list[dict[str, Any]]:
    if not any(r.action in (Action.BLOCK, Action.REDACT) for r in results.values()):
        return messages
    out = copy.deepcopy(messages)
    for (mi, bi), r in results.items():
        if r.action in (Action.BLOCK, Action.REDACT):
            block = out[mi]["content"][bi]
            block["content"] = [{"type": "text", "text": r.content if isinstance(r.content, str) else str(r.content)}]
    return out


def response_tool_calls(response: Mapping[str, Any]) -> list[tuple[int, ToolCall]]:
    out = []
    for i, block in enumerate(response.get("content") or []):
        if block.get("type") == "tool_use":
            inp = block.get("input")
            out.append(
                (
                    i,
                    ToolCall(str(block.get("name")), inp if isinstance(inp, dict) else {}, str(block.get("id"))),
                )
            )
    return out


def rewrite_response(response: dict[str, Any], decisions: Mapping[int, Decision]) -> dict[str, Any]:
    resp = copy.deepcopy(response)
    content = resp.get("content") or []
    new: list[dict[str, Any]] = []
    blocked: list[Decision] = []
    for i, block in enumerate(content):
        d = decisions.get(i)
        if d is not None and not d.allowed:
            blocked.append(d)
            continue
        if d is not None and d.action is Action.REDACT and d.redacted_arguments is not None:
            new.append({**block, "input": d.redacted_arguments})
        else:
            new.append(block)
    if blocked:
        new.append({"type": "text", "text": block_notice(blocked)})
        if not any(b.get("type") == "tool_use" for b in new) and resp.get("stop_reason") == "tool_use":
            resp["stop_reason"] = "end_turn"
    resp["content"] = new
    return resp


class StreamToolBuffer:
    """Buffers SSE events of ``tool_use`` content blocks until their decision is known."""

    def __init__(self) -> None:
        self.blocks: dict[int, dict[str, Any]] = {}
        self.events: dict[int, list[tuple[str, dict[str, Any]]]] = {}

    def is_tool_event(self, event: str, data: Mapping[str, Any]) -> int | None:
        idx = data.get("index")
        if event == "content_block_start" and (data.get("content_block") or {}).get("type") == "tool_use":
            cb = data["content_block"]
            self.blocks[int(idx)] = {"id": cb.get("id"), "name": cb.get("name"), "json": ""}  # type: ignore[arg-type]
            self.events[int(idx)] = []  # type: ignore[arg-type]
            return int(idx)  # type: ignore[arg-type]
        if idx is not None and int(idx) in self.blocks and event in ("content_block_delta", "content_block_stop"):
            delta = data.get("delta") or {}
            if delta.get("type") == "input_json_delta":
                self.blocks[int(idx)]["json"] += delta.get("partial_json", "")
            return int(idx)
        return None

    def tool_calls(self) -> list[tuple[int, ToolCall]]:
        from agentguard.adapters import parse_arguments

        return [
            (i, ToolCall(str(b["name"]), parse_arguments(b["json"] or "{}"), str(b["id"])))
            for i, b in sorted(self.blocks.items())
        ]

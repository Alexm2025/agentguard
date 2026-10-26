"""OpenAI Responses API format (``/v1/responses``), non-streaming."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from typing import Any

from agentguard.adapters import SeenSet, block_notice, parse_arguments
from agentguard.core.engine import Engine, GuardContext, ResultDecision
from agentguard.core.provenance import ProvenanceLedger
from agentguard.core.types import Action, Decision, Origin, ToolCall


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(p.get("text", "")) for p in content if isinstance(p, Mapping) and "text" in p)
    return ""


def ingest(
    engine: Engine,
    ctx: GuardContext,
    instructions: str | None,
    items: Any,
    seen: SeenSet | None = None,
) -> dict[int, ResultDecision]:
    ctx.ledger = ProvenanceLedger(ctx.ledger.session_id)
    if instructions:
        ctx.ledger.add(Origin.DEVELOPER, instructions)
    if isinstance(items, str):
        ctx.ledger.add_user(items)
        return {}
    names: dict[str, tuple[str, dict[str, Any]]] = {}
    results: dict[int, ResultDecision] = {}
    for i, item in enumerate(items or []):
        itype = item.get("type", "message")
        if itype == "message":
            role = item.get("role")
            text = _text(item.get("content"))
            if role in ("system", "developer"):
                ctx.ledger.add(Origin.SYSTEM if role == "system" else Origin.DEVELOPER, text)
            elif role == "user":
                ctx.ledger.add_user(text)
            elif text:
                ctx.ledger.add_assistant(text)
        elif itype == "function_call":
            names[str(item.get("call_id"))] = (str(item.get("name")), parse_arguments(item.get("arguments")))
        elif itype == "function_call_output":
            cid = str(item.get("call_id"))
            tool, args = names.get(cid, ("unknown_tool", {}))
            out = item.get("output")
            emit = seen.add(f"{ctx.session_id}:{cid}") if seen else True
            results[i] = engine.inspect_result(
                ctx,
                tool,
                out if isinstance(out, str) else json.dumps(out),
                arguments=args,
                call_id=cid,
                emit=emit,
            )
    return results


def sanitize_request(items: Any, results: Mapping[int, ResultDecision]) -> Any:
    if isinstance(items, str) or not any(r.action in (Action.BLOCK, Action.REDACT) for r in results.values()):
        return items
    out = list(items)
    for i, r in results.items():
        if r.action in (Action.BLOCK, Action.REDACT):
            out[i] = {**out[i], "output": str(r.content)}
    return out


def response_tool_calls(response: Mapping[str, Any]) -> list[tuple[int, ToolCall]]:
    out = []
    for i, item in enumerate(response.get("output") or []):
        if item.get("type") == "function_call":
            out.append(
                (
                    i,
                    ToolCall(
                        str(item.get("name")),
                        parse_arguments(item.get("arguments")),
                        str(item.get("call_id")),
                    ),
                )
            )
    return out


def rewrite_response(response: dict[str, Any], decisions: Mapping[int, Decision]) -> dict[str, Any]:
    resp = copy.deepcopy(response)
    new, blocked = [], []
    for i, item in enumerate(resp.get("output") or []):
        d = decisions.get(i)
        if d is not None and not d.allowed:
            blocked.append(d)
            continue
        if d is not None and d.action is Action.REDACT and d.redacted_arguments is not None:
            new.append({**item, "arguments": json.dumps(d.redacted_arguments)})
        else:
            new.append(item)
    if blocked:
        notice = block_notice(blocked)
        new.append(
            {
                "type": "message",
                "id": f"msg_agentguard_{blocked[0].event_id}",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": notice, "annotations": []}],
            }
        )
        if "output_text" in resp:
            resp["output_text"] = (resp.get("output_text") or "") + notice
    resp["output"] = new
    return resp

"""Transport-independent MCP message interceptor.

Client -> server:
* ``tools/call`` is evaluated against the policy. Blocked calls are answered locally with a tool
  result (``isError: true``) explaining why, so the agent sees the reason; REQUIRE_APPROVAL waits
  for the approver. Calls to quarantined tools are refused.

Server -> client:
* ``tools/list`` results are scanned for poisoned descriptions; each tool's definition is pinned
  by hash, and a changed definition ("rug pull") is quarantined. Quarantined tools are removed
  from the list returned to the client.
* ``tools/call`` results are recorded as tainted provenance and scanned; per policy they are
  passed through, redacted or withheld.

The MCP gateway does not see the user's prompt. Clients may pass it in
``params._meta["agentguard/user_prompt"]`` of ``tools/call`` so user-requested values are treated
as trusted; otherwise every value that came from a tool result counts as untrusted.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from agentguard.core.approvals import ApprovalStatus, Approver, await_for
from agentguard.core.engine import Engine, GuardContext
from agentguard.core.events import now_iso
from agentguard.core.provenance import ProvenanceLedger
from agentguard.core.types import Action, Decision, Reason, ToolCall

log = logging.getLogger(__name__)
JsonRpc = dict[str, Any]
USER_PROMPT_META = "agentguard/user_prompt"


def tool_digest(tool: dict[str, Any]) -> str:
    material = {k: tool.get(k) for k in ("name", "description", "inputSchema", "outputSchema", "annotations")}
    return hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode()).hexdigest()


class PinStore:
    """First-seen hashes of tool definitions, optionally persisted to a JSON file."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._pins: dict[str, str] = {}
        if self.path and self.path.exists():
            self._pins = json.loads(self.path.read_text(encoding="utf-8"))

    def check(self, key: str, digest: str) -> Literal["new", "same", "changed"]:
        with self._lock:
            cur = self._pins.get(key)
            if cur is None:
                self._pins[key] = digest
                self._save()
                return "new"
            return "same" if cur == digest else "changed"

    def accept(self, key: str, digest: str) -> None:
        with self._lock:
            self._pins[key] = digest
            self._save()

    def _save(self) -> None:
        if self.path:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._pins, indent=2, sort_keys=True), encoding="utf-8")
            tmp.replace(self.path)


@dataclass
class McpSession:
    ctx: GuardContext
    pending: dict[Any, tuple[str, dict[str, Any], str]] = field(default_factory=dict)  # rpc id -> (tool, args, call_id)
    pending_lists: set[Any] = field(default_factory=set)
    quarantined: dict[str, str] = field(default_factory=dict)  # tool -> reason


@dataclass
class ClientVerdict:
    forward: JsonRpc | None  # message to send upstream (possibly unchanged)
    reply: JsonRpc | None  # message to send straight back to the client


class McpInterceptor:
    def __init__(
        self,
        engine: Engine,
        *,
        server_name: str = "mcp",
        approver: Approver | None = None,
        pins: PinStore | None = None,
        on_poisoned: Literal["remove", "allow"] = "remove",
        on_changed: Literal["remove", "allow"] = "remove",
    ) -> None:
        self.engine = engine
        self.server = server_name
        self.approver = approver
        self.pins = pins or PinStore()
        self.on_poisoned = on_poisoned
        self.on_changed = on_changed

    def new_session(
        self, tenant_id: str | None = None, project_id: str | None = None, session_id: str | None = None
    ) -> McpSession:
        return McpSession(GuardContext(ProvenanceLedger(session_id), tenant_id, project_id, source="mcp"))

    # ------------------------------------------------------------------ client -> server

    async def from_client(self, session: McpSession, msg: JsonRpc) -> ClientVerdict:
        method = msg.get("method")
        if method == "tools/list" and "id" in msg:
            session.pending_lists.add(msg["id"])
            return ClientVerdict(msg, None)
        if method != "tools/call" or "id" not in msg:
            return ClientVerdict(msg, None)
        params = msg.get("params") or {}
        name = str(params.get("name", ""))
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            args = {"$value": args}
        meta = params.get("_meta") or {}
        if isinstance(meta, dict) and isinstance(meta.get(USER_PROMPT_META), str):
            prompt = meta[USER_PROMPT_META]
            if prompt not in {s.text for s in session.ctx.ledger.trusted()}:
                session.ctx.ledger.add_user(prompt)
        call = ToolCall(name, args, call_id=f"mcp_{msg['id']}")

        if name in session.quarantined:
            d = Decision(
                Action.BLOCK,
                name,
                call.call_id,
                args,
                reasons=[Reason("QUARANTINED", f"tool '{name}' is quarantined: {session.quarantined[name]}")],
            )
            self.engine._emit(_event(d, session, self.server))
            return ClientVerdict(None, self._blocked_reply(msg, d))

        decision = await asyncio.to_thread(self.engine.evaluate, session.ctx, call)
        if decision.action is Action.REQUIRE_APPROVAL:
            decision = await self._approve(session, decision)
        if not decision.allowed:
            return ClientVerdict(None, self._blocked_reply(msg, decision))
        out = msg
        if decision.action is Action.REDACT and decision.redacted_arguments is not None:
            out = {**msg, "params": {**params, "arguments": decision.redacted_arguments}}
        session.pending[msg["id"]] = (name, args, call.call_id)
        return ClientVerdict(out, None)

    async def _approve(self, session: McpSession, d: Decision) -> Decision:
        if self.approver is None:
            d.action = Action.BLOCK
            d.reasons.append(Reason("NO_APPROVER", "approval required but no approver is configured"))
            return d
        timeout = self.engine.policy.settings.approvals.timeout_seconds
        d.approval_id = await asyncio.to_thread(self.approver.request, d, session.ctx, timeout)
        status = await await_for(self.approver, d.approval_id, timeout)
        if status is ApprovalStatus.APPROVED:
            d.action = Action.ALLOW
            d.reasons.append(Reason("APPROVED", "approved by a human reviewer", action=Action.ALLOW))
        else:
            allow = status is ApprovalStatus.EXPIRED and self.engine.policy.settings.approvals.on_timeout == "ALLOW"
            d.action = Action.ALLOW if allow else Action.BLOCK
            d.reasons.append(
                Reason(
                    "DENIED" if status is ApprovalStatus.DENIED else "APPROVAL_TIMEOUT",
                    f"approval {status.value}",
                    action=d.action,
                )
            )
        self.engine._emit(
            {
                "type": "approval_resolved",
                "id": d.event_id,
                "approval_id": d.approval_id,
                "status": status.value,
                "tool": d.tool,
                **session.ctx.meta(),
            }
        )
        return d

    @staticmethod
    def _blocked_reply(msg: JsonRpc, d: Decision) -> JsonRpc:
        return {
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {
                # Required by the 2026-07-28 schema; ignored by older ones (absent == "complete").
                "resultType": "complete",
                "content": [{"type": "text", "text": d.agent_message()}],
                "isError": True,
                "_meta": {"agentguard/event_id": d.event_id, "agentguard/action": d.action.value},
            },
        }

    # ------------------------------------------------------------------ server -> client

    def from_server(self, session: McpSession, msg: JsonRpc) -> JsonRpc:
        rid = msg.get("id")
        if rid is None or "method" in msg:
            if msg.get("method") == "notifications/tools/list_changed":
                log.info("server %s announced tools/list_changed", self.server)
            return msg
        if rid in session.pending_lists:
            session.pending_lists.discard(rid)
            return self._filter_tool_list(session, msg)
        pending = session.pending.pop(rid, None)
        if pending is None or "result" not in msg:
            return msg
        tool, args, call_id = pending
        result = msg["result"] or {}
        text = _result_text(result)
        rd = self.engine.inspect_result(session.ctx, tool, text, arguments=args, call_id=call_id)
        if rd.action in (Action.BLOCK, Action.REDACT):
            new_result = {k: v for k, v in result.items() if k not in ("content", "structuredContent")}
            new_result["content"] = [{"type": "text", "text": str(rd.content)}]
            new_result.setdefault("_meta", {})["agentguard/action"] = rd.action.value
            return {**msg, "result": new_result}
        return msg

    def _filter_tool_list(self, session: McpSession, msg: JsonRpc) -> JsonRpc:
        result = msg.get("result") or {}
        tools = result.get("tools") or []
        keep = []
        for tool in tools:
            name = str(tool.get("name", ""))
            reason = None
            [finding] = (
                self.engine.inspect_tool_descriptions([tool])
                if self.engine.policy.settings.detectors.scan_tool_descriptions
                else [None]
            )
            if finding is not None and finding.flagged:
                rules = sorted({r for d in finding.detections for r in d.rules})
                reason = f"description looks like a prompt injection ({', '.join(rules[:4])})"
                if self.on_poisoned == "allow":
                    reason = None
            digest = tool_digest(tool)
            state = self.pins.check(f"{self.server}/{name}", digest)
            if state == "changed" and self.on_changed == "remove":
                reason = (
                    reason + "; " if reason else ""
                ) + "definition changed since it was first approved (possible rug pull)"
            if reason:
                session.quarantined[name] = reason
                self.engine._emit(
                    {
                        "type": "mcp_tool_quarantined",
                        "id": f"evt_q_{digest[:16]}",
                        "timestamp": now_iso(),
                        **session.ctx.meta(),
                        "server": self.server,
                        "tool": name,
                        "action": "BLOCK",
                        "reason": reason,
                        "description": str(tool.get("description", ""))[:2000],
                    }
                )
                continue
            session.quarantined.pop(name, None)
            keep.append(tool)
        if len(keep) == len(tools):
            return msg
        return {**msg, "result": {**result, "tools": keep}}


def _result_text(result: dict[str, Any]) -> str:
    parts = []
    for c in result.get("content") or []:
        if c.get("type") == "text":
            parts.append(str(c.get("text", "")))
        elif c.get("type") == "resource":
            res = c.get("resource") or {}
            if "text" in res:
                parts.append(str(res["text"]))
    if result.get("structuredContent") is not None:
        parts.append(json.dumps(result["structuredContent"], ensure_ascii=False, default=str))
    return "\n".join(parts)


def _event(d: Decision, session: McpSession, server: str) -> dict[str, Any]:
    from agentguard.core.events import decision_event

    ev = decision_event(d, context=session.ctx.meta())
    ev["server"] = server
    return ev

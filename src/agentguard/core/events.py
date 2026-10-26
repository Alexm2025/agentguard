"""Security events emitted by the engine, and the sinks that receive them.

Events never contain raw secrets: values that matched DLP patterns are masked, and long strings
are truncated before an event leaves the process.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from agentguard.core.dlp import DEFAULT_SECRET_PATTERNS, DlpScanner
from agentguard.core.types import Decision

log = logging.getLogger("agentguard.events")
MAX_EVENT_STRING = 2000
_scrubber = DlpScanner()


def scrub(value: Any, limit: int = MAX_EVENT_STRING) -> Any:
    """Mask secrets and truncate strings recursively."""
    if isinstance(value, str):
        text = _scrubber.redact_text(value, DEFAULT_SECRET_PATTERNS)
        return text if len(text) <= limit else text[:limit] + f"...[{len(text) - limit} more chars]"
    if isinstance(value, Mapping):
        return {str(k): scrub(v, limit) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [scrub(v, limit) for v in value[:200]]
    return value


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def decision_event(
    decision: Decision, *, kind: str = "tool_call", context: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    ctx = dict(context or {})
    return {
        "id": decision.event_id,
        "type": kind,
        "timestamp": now_iso(),
        "tenant_id": ctx.get("tenant_id"),
        "project_id": ctx.get("project_id"),
        "session_id": ctx.get("session_id"),
        "source": ctx.get("source", "sdk"),
        "tool": decision.tool,
        "call_id": decision.call_id,
        "action": decision.action.value,
        "risk": decision.risk.value,
        "arguments": scrub(decision.arguments),
        "reasons": [
            {"code": r.code, "message": r.message, "rule_id": r.rule_id, "action": r.action.value}
            for r in decision.reasons
        ],
        "taint_chain": decision.taint_chain(),
        "taint_matches": [
            {
                "arg_path": m.arg_path,
                "source": m.source_label,
                "kind": m.kind,
                "score": round(m.score, 4),
                "evidence": scrub(m.evidence, 200),
                "also_in_trusted": m.also_in_trusted,
            }
            for m in decision.taint_matches[:50]
        ],
        "detections": [
            {
                "detector": d.detector,
                "score": d.score,
                "flagged": d.flagged,
                "rules": list(d.rules),
                "latency_ms": round(d.latency_ms, 3),
                "error": d.error,
            }
            for d in decision.detections[:50]
        ],
        "dlp": [{"pattern": f.pattern_id, "arg_path": f.arg_path, "masked": f.masked} for f in decision.dlp_findings],
        "tainted_context": decision.tainted_context,
        "policy": {"name": decision.policy_name, "revision": decision.policy_revision},
        "latency_ms": round(decision.latency_ms, 3),
        "approval_id": decision.approval_id,
        "fail_safe": decision.fail_safe,
    }


class EventSink(Protocol):
    def emit(self, event: dict[str, Any]) -> None: ...


class LoggingSink:
    def __init__(self, level: int = logging.INFO, only_actions: set[str] | None = None) -> None:
        self.level = level
        self.only_actions = only_actions

    def emit(self, event: dict[str, Any]) -> None:
        if self.only_actions and event.get("action") not in self.only_actions:
            return
        log.log(self.level, "%s", json.dumps(event, default=str))


class JsonlFileSink:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def emit(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, default=str, ensure_ascii=False)
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


class MemorySink:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def emit(self, event: dict[str, Any]) -> None:
        self.events.append(event)

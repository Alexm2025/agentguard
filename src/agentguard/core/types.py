"""Value types used across the engine."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Trust(StrEnum):
    TRUSTED = "trusted"
    TAINTED = "tainted"


class Origin(StrEnum):
    SYSTEM = "system"
    DEVELOPER = "developer"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class Action(StrEnum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"

    @property
    def severity(self) -> int:
        return _SEVERITY[self]

    @staticmethod
    def most_severe(actions: list[Action]) -> Action:
        return max(actions, key=lambda a: a.severity, default=Action.ALLOW)


_SEVERITY = {Action.ALLOW: 0, Action.REDACT: 1, Action.REQUIRE_APPROVAL: 2, Action.BLOCK: 3}


class Risk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def level(self) -> int:
        return ("low", "medium", "high", "critical").index(self.value)


class ToolRole(StrEnum):
    SOURCE = "source"
    SINK = "sink"
    BOTH = "both"
    NEUTRAL = "neutral"


class FailMode(StrEnum):
    CLOSED = "closed"
    OPEN = "open"


def new_id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex}"


@dataclass(frozen=True, slots=True)
class Segment:
    """One piece of content that was in the model's context, with its provenance."""

    id: str
    origin: Origin
    trust: Trust
    text: str
    source: str | None = None  # tool name for tool results
    source_ref: str | None = None  # e.g. "read_web(url=https://...)"
    tool_call_id: str | None = None
    turn: int = 0

    @property
    def label(self) -> str:
        if self.origin is Origin.TOOL:
            return self.source_ref or self.source or "tool"
        return self.origin.value


@dataclass(slots=True)
class ToolCall:
    name: str
    arguments: dict[str, Any]
    call_id: str = field(default_factory=lambda: new_id("call_"))


@dataclass(frozen=True, slots=True)
class TaintMatch:
    arg_path: str
    segment_id: str
    source_label: str
    kind: str  # exact | substring | entity | fuzzy | shingle | semantic | decoded
    score: float
    evidence: str
    also_in_trusted: bool = False

    @property
    def derived(self) -> bool:
        """True when the value is attributable to tainted content only."""
        return not self.also_in_trusted

    def chain(self, tool: str) -> str:
        return f"{tool}.{self.arg_path} derived from {self.source_label} ({self.kind}, score={self.score:.2f})"


@dataclass(frozen=True, slots=True)
class Detection:
    detector: str
    score: float
    flagged: bool
    segment_id: str | None = None
    rules: tuple[str, ...] = ()
    latency_ms: float = 0.0
    error: str | None = None


@dataclass(frozen=True, slots=True)
class DlpFinding:
    pattern_id: str
    arg_path: str
    masked: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class Reason:
    code: str
    message: str
    rule_id: str | None = None
    action: Action = Action.BLOCK


@dataclass(slots=True)
class Decision:
    """Outcome of evaluating a tool call (or a tool result)."""

    action: Action
    tool: str
    call_id: str
    arguments: dict[str, Any]
    reasons: list[Reason] = field(default_factory=list)
    taint_matches: list[TaintMatch] = field(default_factory=list)
    detections: list[Detection] = field(default_factory=list)
    dlp_findings: list[DlpFinding] = field(default_factory=list)
    redacted_arguments: dict[str, Any] | None = None
    risk: Risk = Risk.LOW
    tainted_context: bool = False
    policy_name: str = ""
    policy_revision: int = 0
    latency_ms: float = 0.0
    event_id: str = field(default_factory=lambda: new_id("evt_"))
    approval_id: str | None = None
    fail_safe: bool = False

    @property
    def allowed(self) -> bool:
        return self.action in (Action.ALLOW, Action.REDACT)

    @property
    def effective_arguments(self) -> dict[str, Any]:
        if self.action is Action.REDACT and self.redacted_arguments is not None:
            return self.redacted_arguments
        return self.arguments

    def taint_chain(self) -> list[str]:
        return [m.chain(self.tool) for m in self.taint_matches if m.derived]

    def agent_message(self) -> str:
        """Message returned to the agent in place of the tool result."""
        if self.action is Action.BLOCK:
            head = f"AgentGuard blocked the call to '{self.tool}'."
        elif self.action is Action.REQUIRE_APPROVAL:
            head = f"AgentGuard requires human approval for the call to '{self.tool}'."
        else:
            head = f"AgentGuard modified the call to '{self.tool}'."
        why = "; ".join(r.message for r in self.reasons) or "policy decision"
        return (
            f"{head} Reason: {why}. Do not retry this action with the same arguments; "
            f"continue with the user's original task or ask the user how to proceed. (event {self.event_id})"
        )

"""Provider wire-format adapters shared by the SDK wrappers and the LLM API gateway.

They work on plain JSON-like dicts: they rebuild a provenance ledger from a request's message
list (so no server-side session state is needed), inspect tool results, evaluate the tool calls in
a response, and rewrite responses to remove blocked calls.
"""

from __future__ import annotations

import json
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from agentguard.core.types import Decision


class SeenSet:
    """Bounded set used to emit each tool-result event once across repeated requests."""

    def __init__(self, size: int = 50_000) -> None:
        self._d: OrderedDict[str, None] = OrderedDict()
        self._size = size

    def add(self, key: str) -> bool:
        """Return True if the key was new."""
        if key in self._d:
            self._d.move_to_end(key)
            return False
        self._d[key] = None
        if len(self._d) > self._size:
            self._d.popitem(last=False)
        return True


def parse_arguments(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if raw is None or raw == "":
        return {}
    try:
        val = json.loads(raw)
    except (TypeError, ValueError):
        return {"$raw": str(raw)}
    return val if isinstance(val, dict) else {"$value": val}


@dataclass
class CallOutcome:
    decisions: list[Decision] = field(default_factory=list)

    @property
    def blocked(self) -> list[Decision]:
        return [d for d in self.decisions if not d.allowed]

    @property
    def any_blocked(self) -> bool:
        return any(not d.allowed for d in self.decisions)


def block_notice(decisions: list[Decision]) -> str:
    return "\n".join(d.agent_message() for d in decisions)

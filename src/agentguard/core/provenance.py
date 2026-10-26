"""Provenance ledger: records every piece of context together with its trust label."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterable, Mapping
from typing import Any

from agentguard.core.types import Origin, Segment, Trust, new_id

MAX_REF_VALUE = 120


def describe_call(tool: str, arguments: Mapping[str, Any] | None, ref_arg: str | None = None) -> str:
    """Human readable reference for a tool invocation, e.g. ``read_web(url=https://x)``."""
    if not arguments:
        return f"{tool}()"
    if ref_arg and ref_arg in arguments:
        items: Iterable[tuple[str, Any]] = [(ref_arg, arguments[ref_arg])]
    else:
        items = list(arguments.items())[:2]
    parts = []
    for key, value in items:
        text = value if isinstance(value, str) else json.dumps(value, default=str)
        if len(text) > MAX_REF_VALUE:
            text = text[: MAX_REF_VALUE - 3] + "..."
        parts.append(f"{key}={text}")
    return f"{tool}({', '.join(parts)})"


def content_to_text(content: Any) -> str:
    """Flatten message/tool-result content (str, list of parts, dicts) into plain text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace")
    if isinstance(content, Mapping):
        for key in ("text", "content", "output", "result"):
            if key in content and isinstance(content[key], str | list | dict):
                return content_to_text(content[key])
        return json.dumps(content, default=str, ensure_ascii=False)
    if isinstance(content, list | tuple):
        return "\n".join(t for t in (content_to_text(c) for c in content) if t)
    return str(content)


class ProvenanceLedger:
    """Ordered, thread-safe list of context segments for one agent session.

    Trust rules:
    * system / developer / user content is TRUSTED;
    * tool results are TAINTED unless the tool is configured as trusted;
    * assistant content inherits taint if any tainted content preceded it, because the model may
      have been steered by it.
    """

    def __init__(self, session_id: str | None = None) -> None:
        self.session_id = session_id or new_id("ses_")
        self._segments: list[Segment] = []
        self._lock = threading.Lock()
        self._turn = 0

    def __len__(self) -> int:
        return len(self._segments)

    @property
    def segments(self) -> list[Segment]:
        with self._lock:
            return list(self._segments)

    def _add(self, segment: Segment) -> Segment:
        with self._lock:
            self._segments.append(segment)
        return segment

    def add(
        self,
        origin: Origin,
        text: str,
        *,
        trust: Trust | None = None,
        source: str | None = None,
        source_ref: str | None = None,
        tool_call_id: str | None = None,
    ) -> Segment:
        if trust is None:
            if origin in (Origin.SYSTEM, Origin.DEVELOPER, Origin.USER):
                trust = Trust.TRUSTED
            elif origin is Origin.ASSISTANT:
                trust = Trust.TAINTED if self.has_taint() else Trust.TRUSTED
            else:
                trust = Trust.TAINTED
        if origin is Origin.USER:
            self._turn += 1
        return self._add(
            Segment(
                id=new_id("seg_"),
                origin=origin,
                trust=trust,
                text=text,
                source=source,
                source_ref=source_ref,
                tool_call_id=tool_call_id,
                turn=self._turn,
            )
        )

    def add_system(self, text: str) -> Segment:
        return self.add(Origin.SYSTEM, text)

    def add_user(self, text: str) -> Segment:
        return self.add(Origin.USER, text)

    def add_assistant(self, text: str) -> Segment:
        return self.add(Origin.ASSISTANT, text)

    def add_tool_result(
        self,
        tool: str,
        content: Any,
        *,
        arguments: Mapping[str, Any] | None = None,
        trusted: bool = False,
        ref_arg: str | None = None,
        tool_call_id: str | None = None,
    ) -> Segment:
        return self.add(
            Origin.TOOL,
            content_to_text(content),
            trust=Trust.TRUSTED if trusted else Trust.TAINTED,
            source=tool,
            source_ref=describe_call(tool, arguments, ref_arg),
            tool_call_id=tool_call_id,
        )

    def has_taint(self) -> bool:
        return any(s.trust is Trust.TAINTED for s in self._segments)

    def tainted(self) -> list[Segment]:
        return [s for s in self.segments if s.trust is Trust.TAINTED and s.text]

    def trusted(self) -> list[Segment]:
        return [s for s in self.segments if s.trust is Trust.TRUSTED and s.text]

    def tainted_sources(self) -> list[str]:
        return [s.label for s in self.tainted() if s.origin is Origin.TOOL]

    def user_task(self) -> str:
        return "\n".join(s.text for s in self.segments if s.origin is Origin.USER)

    def get(self, segment_id: str) -> Segment | None:
        return next((s for s in self._segments if s.id == segment_id), None)

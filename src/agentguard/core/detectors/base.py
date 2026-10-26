"""Detector protocol and the layered detector that combines them."""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from agentguard.core.types import Detection

log = logging.getLogger(__name__)


@runtime_checkable
class Detector(Protocol):
    name: str
    threshold: float

    def score(self, text: str) -> tuple[float, tuple[str, ...]]:
        """Return an injection probability in [0, 1] and the ids of the rules that fired."""
        ...


def run_detector(detector: Detector, text: str, segment_id: str | None = None) -> Detection:
    start = time.perf_counter()
    try:
        score, rules = detector.score(text)
    except Exception as exc:  # detectors must never take the engine down
        log.exception("detector %s failed", detector.name)
        return Detection(detector.name, 0.0, False, segment_id, (), _ms(start), error=type(exc).__name__)
    return Detection(detector.name, score, score >= detector.threshold, segment_id, rules, _ms(start))


def _ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000.0


class LayeredDetector:
    """Runs detectors in order. With ``short_circuit``, later (more expensive) layers are skipped
    once an earlier layer flags the text."""

    def __init__(self, detectors: Sequence[Detector], short_circuit: bool = False) -> None:
        self.detectors = list(detectors)
        self.short_circuit = short_circuit

    def detect(self, text: str, segment_id: str | None = None) -> list[Detection]:
        results: list[Detection] = []
        for det in self.detectors:
            d = run_detector(det, text, segment_id)
            results.append(d)
            if d.flagged and self.short_circuit:
                break
        return results

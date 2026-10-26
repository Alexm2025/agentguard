from __future__ import annotations

import os

import pytest

from agentguard.core.detectors.heuristic import HeuristicDetector
from agentguard.core.engine import Engine, GuardContext
from agentguard.core.events import MemorySink
from agentguard.core.policy.loader import default_policy, parse_policy

# Keep unit tests deterministic regardless of whether a trained model is present on the machine.
os.environ.setdefault("AGENTGUARD_MODEL_DIR", os.path.join(os.path.dirname(__file__), "_no_model_"))


@pytest.fixture
def sink() -> MemorySink:
    return MemorySink()


@pytest.fixture
def engine(sink: MemorySink) -> Engine:
    return Engine(default_policy(), detectors=[HeuristicDetector()], sinks=[sink])


@pytest.fixture
def ctx() -> GuardContext:
    c = GuardContext(tenant_id="t1", project_id="p1")
    c.ledger.add_system("You are a helpful email assistant for ACME Corp.")
    return c


def make_policy(yaml_text: str):  # type: ignore[no-untyped-def]
    return parse_policy(yaml_text)

"""Property-based tests for the taint matcher."""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from agentguard.core.normalize import normalize
from agentguard.core.provenance import ProvenanceLedger
from agentguard.core.taint import TaintMatcher

WORD = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=2, max_size=9)
TEXT = st.lists(WORD, min_size=4, max_size=60).map(" ".join)

matcher = TaintMatcher()


def ledger(user: str, tool: str) -> ProvenanceLedger:
    led = ProvenanceLedger()
    led.add_user(user)
    led.add_tool_result("read_web", tool)
    return led


@settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
@given(TEXT, st.data())
def test_any_long_substring_of_tainted_is_detected(text: str, data: st.DataObject) -> None:
    norm = normalize(text)
    if len(norm) < 8:
        return
    start = data.draw(st.integers(0, len(norm) - 8))
    end = data.draw(st.integers(start + 8, len(norm)))
    piece = norm[start:end]
    if len(piece.strip()) < 8:
        return
    led = ledger("do the task", text)
    assert matcher.match({"x": piece}, led.tainted(), led.trusted()), piece


@settings(max_examples=100)
@given(TEXT)
def test_case_and_whitespace_invariance(text: str) -> None:
    led = ledger("task", text)
    variant = "  " + text.upper().replace(" ", " \t\n ") + "  "
    a = matcher.match({"x": text}, led.tainted(), led.trusted())
    b = matcher.match({"x": variant}, led.tainted(), led.trusted())
    assert bool(a) == bool(b)
    assert a and b


@settings(max_examples=100)
@given(TEXT)
def test_value_also_in_trusted_is_never_derived(text: str) -> None:
    led = ledger(text, text)
    for m in matcher.match({"x": text}, led.tainted(), led.trusted()):
        assert not m.derived


@settings(max_examples=100)
@given(
    st.lists(st.text(alphabet="abcdefghij", min_size=3, max_size=8), min_size=3, max_size=30).map(" ".join),
    st.lists(st.text(alphabet="qrstuvwxyz", min_size=3, max_size=8), min_size=1, max_size=10).map(" ".join),
)
def test_disjoint_alphabets_never_match(tainted: str, value: str) -> None:
    led = ledger("task", tainted)
    assert matcher.match({"x": value}, led.tainted(), led.trusted()) == []


@settings(max_examples=50)
@given(
    st.recursive(
        st.text(max_size=20) | st.integers() | st.booleans() | st.none(),
        lambda c: st.lists(c, max_size=4) | st.dictionaries(st.text(min_size=1, max_size=5), c, max_size=4),
        max_leaves=20,
    ),
    TEXT,
)
def test_matcher_never_crashes_on_arbitrary_json(args: object, text: str) -> None:
    led = ledger("task", text)
    matcher.match({"root": args}, led.tainted(), led.trusted())

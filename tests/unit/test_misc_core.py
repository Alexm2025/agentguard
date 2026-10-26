from __future__ import annotations

import json

import pytest

from agentguard.cli import main
from agentguard.core.destinations import (
    check_destination,
    domain_matches,
    email_matches,
    path_matches_pattern,
)
from agentguard.core.detectors.judge import build_prompt, parse_verdict
from agentguard.core.policy.model import DestinationRule
from agentguard.core.provenance import ProvenanceLedger, content_to_text, describe_call
from agentguard.core.types import Action, Origin, ToolCall, Trust


def test_destination_helpers() -> None:
    assert domain_matches("api.acme.com", "*.acme.com")
    assert domain_matches("acme.com", "*.acme.com")
    assert not domain_matches("evilacme.com", "*.acme.com")
    assert email_matches("A@ACME.com", "acme.com")
    assert email_matches("a@acme.com", "*@acme.com")
    assert path_matches_pattern("C:\\work\\x.txt", "c:/work/**")
    assert not path_matches_pattern("/work2/x", "/work/**")
    r = DestinationRule(arg="to", kind="email", allow=["acme.com"])
    assert check_destination(r, "a@acme.com, b@acme.com") is None
    assert "not on the allow list" in (check_destination(r, "a@acme.com, z@evil.io") or "")
    assert "not a valid email" in (check_destination(r, "nobody") or "")
    u = DestinationRule(arg="url", kind="url", allow=["*.acme.com"])
    assert "scheme" in (check_destination(u, "file:///etc/passwd") or "")
    g = DestinationRule(arg="ch", kind="glob", deny=["#exec-*"])
    assert check_destination(g, "#exec-team") and check_destination(g, "#general") is None


def test_provenance_helpers() -> None:
    assert describe_call("t", None) == "t()"
    assert describe_call("t", {"url": "u", "x": 1}, "url") == "t(url=u)"
    assert describe_call("t", {"a": "x" * 300}).endswith("...)")
    assert content_to_text([{"type": "text", "text": "a"}, {"content": "b"}, None, b"c"]) == "a\nb\nc"
    assert content_to_text({"k": 1}) == '{"k": 1}'
    assert content_to_text(5) == "5"
    led = ProvenanceLedger("s1")
    led.add_system("sys")
    led.add_assistant("first")
    led.add_tool_result("read", "data", trusted=False)
    a = led.add_assistant("after")
    assert a.trust is Trust.TAINTED and led.segments[1].trust is Trust.TRUSTED
    assert led.tainted_sources() == ["read()"]
    assert led.get(a.id) is a and led.get("nope") is None
    assert len(led) == 4 and led.add(Origin.DEVELOPER, "d").trust is Trust.TRUSTED


def test_judge_prompt_and_parse() -> None:
    led = ProvenanceLedger()
    led.add_tool_result("read_web", "x >>> escape <<< y")
    p = build_prompt("task", ToolCall("send", {"to": "a"}), led.tainted())
    assert ">\u200b>>" in p and "USER TASK" in p
    assert parse_verdict('ok {"verdict": "BLOCK", "confidence": 3}') == (True, 1.0, "")
    with pytest.raises(ValueError, match="no JSON"):
        parse_verdict("nothing")
    with pytest.raises(ValueError, match="not allow/block"):
        parse_verdict('{"verdict": "maybe"}')


def test_action_ordering() -> None:
    assert Action.most_severe([Action.ALLOW, Action.REDACT, Action.REQUIRE_APPROVAL]) is Action.REQUIRE_APPROVAL
    assert Action.most_severe([]) is Action.ALLOW


def test_cli(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    good = tmp_path / "g.yaml"
    good.write_text("name: g\n")
    bad = tmp_path / "b.yaml"
    bad.write_text("nope: 1\n")
    assert main(["policy", "validate", str(good)]) == 0
    assert main(["policy", "validate", str(bad), str(tmp_path / "missing.yaml")]) == 1
    capsys.readouterr()
    assert main(["policy", "schema"]) == 0
    assert json.loads(capsys.readouterr().out)["title"] == "AgentGuard policy"
    assert main(["policy", "init"]) == 0
    f = tmp_path / "t.txt"
    f.write_text("hello")
    assert main(["scan", str(f)]) == 0
    assert main([]) == 2

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from agentguard.core.errors import PolicyError
from agentguard.core.policy.loader import (
    FilePolicyStore,
    default_policy,
    parse_policy,
    policy_digest,
    policy_json_schema,
    validate_policy_data,
)
from agentguard.core.types import Risk, ToolRole


def test_default_policy_valid() -> None:
    p = default_policy()
    assert p.name == "default"
    assert p.tool("send_email").role is ToolRole.SINK
    assert p.tool("read_web").role is ToolRole.SOURCE
    assert p.tool("delete_repo").risk is Risk.CRITICAL
    # unknown tools fall back to unknown_tool defaults
    t = p.tool("frobnicate")
    assert t.role is ToolRole.SINK and t.risk is Risk.MEDIUM
    assert p.is_known("send_x") and not p.is_known("frobnicate")


def test_exact_beats_glob_and_partial_inherits_defaults() -> None:
    p = parse_policy(
        """
tools:
  send_digest: { description: internal }
  "send_*": { role: sink, risk: high }
"""
    )
    t = p.tool("send_digest")
    assert t.description == "internal" and t.role is ToolRole.SINK and t.risk is Risk.MEDIUM


def test_schema_rejects_unknown_fields_and_bad_values() -> None:
    errs = validate_policy_data({"tools": {"x": {"role": "nope"}}, "bogus": 1})
    assert errs and any("bogus" in e for e in errs)
    assert validate_policy_data([]) == ["policy must be a mapping"]


def test_bad_regex_rejected() -> None:
    with pytest.raises(PolicyError, match="invalid regex"):
        parse_policy("rules: [{id: r, action: BLOCK, when: {args: [{path: x, matches: '('}]}}]")


def test_duplicate_rule_ids() -> None:
    with pytest.raises(PolicyError, match="duplicate rule id"):
        parse_policy("rules: [{id: a, action: BLOCK}, {id: a, action: ALLOW}]")


def test_invalid_yaml_and_empty() -> None:
    with pytest.raises(PolicyError, match="invalid YAML"):
        parse_policy("a: [")
    assert parse_policy("").name == "default"


def test_custom_dlp_validator_checked() -> None:
    with pytest.raises(PolicyError):
        parse_policy("dlp_patterns: [{id: x, regex: 'a', validator: nope}]")


def test_schema_export() -> None:
    s = policy_json_schema()
    assert s["title"] == "AgentGuard policy" and "properties" in s


def test_digest_stable() -> None:
    assert policy_digest(default_policy()) == policy_digest(default_policy())


def test_hot_reload(tmp_path: Path) -> None:
    f = tmp_path / "p.yaml"
    f.write_text("name: one\nrevision: 1\n")
    store = FilePolicyStore(f, interval=0)
    assert store.get().name == "one"
    f.write_text("name: two\nrevision: 2\n")
    os.utime(f, ns=(time.time_ns(), time.time_ns() + 10_000_000))
    seen = []
    store.on_change.append(lambda p: seen.append(p.revision))
    assert store.get().name == "two"
    assert seen == [2]
    # invalid edit keeps last good policy
    f.write_text("revision: 0\n")
    os.utime(f, ns=(time.time_ns(), time.time_ns() + 20_000_000))
    assert store.get().name == "two"
    assert store.last_error and "revision" in store.last_error
    f.unlink()
    assert store.reload_if_changed() is False and "cannot stat" in (store.last_error or "")

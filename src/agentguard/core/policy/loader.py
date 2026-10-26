"""Loading, validation and hot reload of policies."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

import jsonschema
import yaml
from pydantic import ValidationError

from agentguard.core.errors import PolicyError
from agentguard.core.policy.model import Policy

log = logging.getLogger(__name__)

MAX_POLICY_BYTES = 1_000_000


@lru_cache(maxsize=1)
def policy_json_schema() -> dict[str, Any]:
    schema = Policy.model_json_schema(by_alias=True)
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "https://agentguard.dev/schemas/policy-v1.json"
    schema["title"] = "AgentGuard policy"
    return schema


def _format_path(path: Any) -> str:
    return ".".join(str(p) for p in path) or "<root>"


def validate_policy_data(data: Any) -> list[str]:
    """Return a list of human-readable validation errors (empty if valid)."""
    if not isinstance(data, dict):
        return ["policy must be a mapping"]
    validator = jsonschema.Draft202012Validator(policy_json_schema())
    errors = [f"{_format_path(e.absolute_path)}: {e.message}" for e in validator.iter_errors(data)]
    if errors:
        return sorted(errors)
    try:
        Policy.model_validate(data)
    except ValidationError as exc:
        return [f"{_format_path(err['loc'])}: {err['msg']}" for err in exc.errors()]
    return []


def _deep_merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in over.items():
        out[k] = _deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def merge_with_default(data: dict[str, Any]) -> dict[str, Any]:
    """Layer a user policy over the default policy (see ``Policy.extends``)."""
    base = yaml.safe_load(default_policy_text())
    merged: dict[str, Any] = {k: v for k, v in data.items() if k not in ("settings", "tools", "rules", "dlp_patterns")}
    merged["extends"] = "none"
    merged["settings"] = _deep_merge(base.get("settings", {}), data.get("settings") or {})
    # User tool keys first so they win over the default glob patterns.
    tools = dict(data.get("tools") or {})
    for k, v in (base.get("tools") or {}).items():
        tools.setdefault(k, v)
    merged["tools"] = tools
    user_rules = list(data.get("rules") or [])
    user_ids = {r.get("id") for r in user_rules if isinstance(r, dict)}
    merged["rules"] = [r for r in base.get("rules", []) if r.get("id") not in user_ids] + user_rules
    merged["dlp_patterns"] = list(base.get("dlp_patterns") or []) + list(data.get("dlp_patterns") or [])
    return merged


def parse_policy(text: str) -> Policy:
    if len(text.encode()) > MAX_POLICY_BYTES:
        raise PolicyError("policy document too large")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid YAML: {exc}") from exc
    if data is None:
        data = {}
    errors = validate_policy_data(data)
    if errors:
        raise PolicyError("invalid policy:\n  " + "\n  ".join(errors))
    if data.get("extends", "default") == "default":
        data = merge_with_default(data)
        errors = validate_policy_data(data)
        if errors:
            raise PolicyError("invalid policy after merging with default:\n  " + "\n  ".join(errors))
    return Policy.model_validate(data)


def load_policy(path: str | Path) -> Policy:
    return parse_policy(Path(path).read_text(encoding="utf-8"))


def default_policy_text() -> str:
    return resources.files("agentguard.core.policy").joinpath("default.yaml").read_text(encoding="utf-8")


def default_policy() -> Policy:
    return parse_policy(default_policy_text())


def policy_digest(policy: Policy) -> str:
    return hashlib.sha256(json.dumps(policy.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()


class PolicyStore:
    """Holds the active policy. Thread-safe; supports in-place replacement."""

    def __init__(self, policy: Policy | None = None) -> None:
        self._policy = policy or default_policy()
        self._lock = threading.Lock()
        self.on_change: list[Any] = []

    def get(self) -> Policy:
        return self._policy

    def set(self, policy: Policy) -> None:
        with self._lock:
            old, self._policy = self._policy, policy
        if old is not policy:
            for cb in self.on_change:
                cb(policy)


class FilePolicyStore(PolicyStore):
    """Policy backed by a YAML file, reloaded when its mtime changes.

    Reload is checked lazily (at most every ``interval`` seconds) on ``get()``, so no background
    thread is needed. An invalid edit is logged and the last good policy stays active.
    """

    def __init__(self, path: str | Path, interval: float = 2.0) -> None:
        self.path = Path(path)
        self.interval = interval
        self._mtime = self.path.stat().st_mtime_ns
        self._checked = time.monotonic()
        self.last_error: str | None = None
        super().__init__(load_policy(self.path))

    def get(self) -> Policy:
        now = time.monotonic()
        if now - self._checked >= self.interval:
            self._checked = now
            self.reload_if_changed()
        return super().get()

    def reload_if_changed(self) -> bool:
        try:
            mtime = self.path.stat().st_mtime_ns
        except OSError as exc:
            self.last_error = f"cannot stat policy file: {exc}"
            log.error("policy reload failed: %s", self.last_error)
            return False
        if mtime == self._mtime:
            return False
        self._mtime = mtime
        try:
            policy = load_policy(self.path)
        except (PolicyError, OSError) as exc:
            self.last_error = str(exc)
            log.error("policy reload failed, keeping revision %s: %s", self._policy.revision, exc)
            return False
        self.last_error = None
        log.info("policy reloaded: %s revision %s", policy.name, policy.revision)
        self.set(policy)
        return True

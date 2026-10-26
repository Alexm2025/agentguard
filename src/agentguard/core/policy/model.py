"""Declarative policy model. YAML files are validated against the JSON Schema generated from
these models (``agentguard policy schema``) and then parsed into them."""

from __future__ import annotations

import re
from fnmatch import fnmatchcase
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentguard.core.dlp import VALIDATORS
from agentguard.core.types import Action, FailMode, Risk, ToolRole

MAX_REGEX_LEN = 512
Name = Annotated[str, Field(min_length=1, max_length=200, pattern=r"^[\w.\-:/*?\[\]]+$")]


def _check_regex(value: str | None) -> str | None:
    if value is None:
        return value
    if len(value) > MAX_REGEX_LEN:
        raise ValueError(f"regex longer than {MAX_REGEX_LEN} characters")
    try:
        re.compile(value)
    except re.error as exc:
        raise ValueError(f"invalid regex: {exc}") from exc
    return value


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)


class DestinationRule(_Model):
    """Allow/deny list for an argument that names where data goes."""

    arg: str = Field(description="Argument path, e.g. `to` or `recipients.*`.")
    kind: Literal["email", "domain", "url", "path", "glob"]
    allow: list[str] = Field(default_factory=list, description="Glob patterns; empty means allow all not denied.")
    deny: list[str] = Field(default_factory=list)
    on_violation: Action = Action.BLOCK


class RateLimit(_Model):
    max_calls: int = Field(gt=0, le=1_000_000)
    per_seconds: float = Field(gt=0, le=86_400 * 31)
    scope: Literal["session", "project", "tenant"] = "session"
    on_exceed: Action = Action.BLOCK


class ToolDlp(_Model):
    patterns: list[str] = Field(min_length=1)
    on_match: Action = Action.BLOCK


class ResultPolicy(_Model):
    scan: bool = True
    on_injection: Action = Field(
        default=Action.ALLOW,
        description="ALLOW keeps the result (it stays tainted and is tracked); REDACT replaces flagged "
        "content with a notice; BLOCK withholds the whole result.",
    )
    dlp: ToolDlp | None = None


class ToolPolicy(_Model):
    description: str = ""
    role: ToolRole | None = None
    risk: Risk | None = None
    trusted_output: bool = Field(default=False, description="Treat this tool's results as trusted.")
    ref_arg: str | None = Field(default=None, description="Argument identifying the source, e.g. `url`.")
    destination_args: list[str] = Field(
        default_factory=list, description="Arguments that select a recipient/target (e.g. `to`, `url`)."
    )
    destinations: list[DestinationRule] = Field(default_factory=list)
    rate_limit: RateLimit | None = None
    dlp: ToolDlp | None = None
    fail_mode: FailMode | None = None
    judge: bool | None = Field(default=None, description="Force the LLM judge on/off for this tool.")
    result: ResultPolicy = Field(default_factory=ResultPolicy)
    action: Action | None = Field(default=None, description="Unconditional action for this tool.")


class ArgCondition(_Model):
    path: str
    matches: str | None = None
    not_matches: str | None = None
    equals: str | int | float | bool | None = None
    one_of: list[str] | None = Field(default=None, alias="in")
    min_len: int | None = None
    max_len: int | None = None

    _v_matches = field_validator("matches", "not_matches")(_check_regex)


class When(_Model):
    tainted_context: bool | None = Field(default=None, description="Any tainted content in context.")
    tainted_args: list[str] | Literal["any", "destination"] | None = Field(
        default=None,
        description="Arguments whose value is derived from tainted content. `destination` means the "
        "tool's `destination_args` (and destination rule args).",
    )
    taint_kinds: list[str] | None = Field(
        default=None, description="Restrict tainted_args to these match kinds (prefix match, e.g. `entity`)."
    )
    min_taint_score: float = Field(default=0.0, ge=0, le=1)
    injection_detected: bool | None = Field(default=None, description="A detector flagged tainted content.")
    min_injection_score: float = Field(default=0.0, ge=0, le=1)
    dlp: list[str] | Literal["any"] | None = None
    destination_violation: bool | None = None
    args: list[ArgCondition] = Field(default_factory=list)
    judge_flagged: bool | None = None


class Rule(_Model):
    id: str = Field(min_length=1, max_length=100, pattern=r"^[\w.\-]+$")
    description: str = ""
    enabled: bool = True
    tools: list[Name] = Field(default_factory=lambda: ["*"])
    roles: list[ToolRole] | None = None
    min_risk: Risk | None = None
    when: When = Field(default_factory=When)
    action: Action
    message: str | None = None
    override: bool = Field(default=False, description="An ALLOW rule with override=true wins over others.")


class CustomDlpPattern(_Model):
    id: str = Field(pattern=r"^[a-z0-9_]+$")
    regex: str
    validator: str = "none"
    category: Literal["secret", "pii", "custom"] = "custom"

    _v_regex = field_validator("regex")(_check_regex)

    @field_validator("validator")
    @classmethod
    def _v_validator(cls, v: str) -> str:
        if v not in VALIDATORS:
            raise ValueError(f"unknown validator {v!r}; choose from {sorted(VALIDATORS)}")
        return v


class TaintSettings(_Model):
    min_substring_len: int = Field(default=8, ge=3)
    fuzzy_threshold: float = Field(default=88.0, ge=50, le=100)
    shingle_containment: float = Field(default=0.6, gt=0, le=1)
    semantic: bool = False
    semantic_threshold: float = Field(default=0.82, gt=0, le=1)
    decode: bool = True


class HeuristicSettings(_Model):
    enabled: bool = True
    threshold: float = Field(default=0.5, ge=0, le=1)


class MlSettings(_Model):
    enabled: bool = True
    model: str = Field(default="auto", description="Path to the ONNX model directory, or `auto`.")
    threshold: float = Field(default=0.85, ge=0, le=1)
    required: bool = Field(default=False, description="Fail if the model cannot be loaded.")
    min_words: int = Field(default=4, ge=0, description="Skip the ML layer for texts with fewer words.")


class JudgeSettings(_Model):
    enabled: bool = False
    provider: Literal["openai", "anthropic"] = "openai"
    model: str = "gpt-4.1-mini"
    min_risk: Risk = Risk.HIGH
    only_when_tainted: bool = True
    timeout_seconds: float = Field(default=8.0, gt=0, le=120)
    base_url: str | None = None
    on_block: Literal["BLOCK", "REQUIRE_APPROVAL"] = "BLOCK"
    min_confidence: float = Field(default=0.5, ge=0, le=1)


class DetectorSettings(_Model):
    heuristic: HeuristicSettings = Field(default_factory=HeuristicSettings)
    ml: MlSettings = Field(default_factory=MlSettings)
    judge: JudgeSettings = Field(default_factory=JudgeSettings)
    scan_tool_descriptions: bool = True


class ApprovalSettings(_Model):
    timeout_seconds: float = Field(default=300, gt=0, le=86_400)
    on_timeout: Literal["BLOCK", "ALLOW"] = "BLOCK"


class Settings(_Model):
    fail_mode: FailMode = FailMode.CLOSED
    fail_open_max_risk: Risk = Field(
        default=Risk.MEDIUM, description="With fail_mode=open, tools above this risk still fail closed."
    )
    default_action: Action = Action.ALLOW
    unknown_tool: ToolPolicy = Field(
        default_factory=lambda: ToolPolicy(role=ToolRole.SINK, risk=Risk.MEDIUM),
        description="Defaults for tools not listed under `tools`.",
    )
    taint: TaintSettings = Field(default_factory=TaintSettings)
    detectors: DetectorSettings = Field(default_factory=DetectorSettings)
    approvals: ApprovalSettings = Field(default_factory=ApprovalSettings)
    max_argument_chars: int = Field(default=1_000_000, gt=0)


class Policy(_Model):
    version: Literal[1] = Field(default=1, description="Policy schema version.")
    extends: Literal["default", "none"] = Field(
        default="default",
        description="`default` layers this policy over the built-in default policy (your tools are "
        "matched first, rules with the same id replace default rules). `none` starts empty.",
    )
    name: str = Field(default="default", min_length=1, max_length=100)
    revision: int = Field(default=1, ge=1, description="Monotonic policy revision.")
    description: str = ""
    settings: Settings = Field(default_factory=Settings)
    tools: dict[str, ToolPolicy] = Field(default_factory=dict, description="Keys may be glob patterns.")
    dlp_patterns: list[CustomDlpPattern] = Field(default_factory=list)
    rules: list[Rule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> Policy:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id {rule.id!r}")
            seen.add(rule.id)
        return self

    def tool(self, name: str) -> ToolPolicy:
        """Resolve a tool's policy: exact key, then first matching glob key, then defaults.
        Unset fields fall back to ``settings.unknown_tool``."""
        found = self.tools.get(name)
        if found is None:
            found = next((tp for key, tp in self.tools.items() if fnmatchcase(name, key)), None)
        base = self.settings.unknown_tool
        if found is None:
            return base
        updates: dict[str, Any] = {}
        if found.role is None:
            updates["role"] = base.role
        if found.risk is None:
            updates["risk"] = base.risk
        return found.model_copy(update=updates) if updates else found

    def is_known(self, name: str) -> bool:
        return name in self.tools or any(fnmatchcase(name, k) for k in self.tools)

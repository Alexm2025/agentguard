"""Data-loss-prevention scanning: secrets, credentials and PII via regex + validators."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from agentguard.core.taint import flatten_arguments
from agentguard.core.types import DlpFinding


def luhn(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if not 12 <= len(digits) <= 19:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        d = digit * 2 if i % 2 == 1 else digit
        total += d - 9 if d > 9 else d
    return total % 10 == 0


def iban(value: str) -> bool:
    s = re.sub(r"\s", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in rearranged)
    return int(num) % 97 == 1


def us_ssn(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    return area not in ("000", "666") and not area.startswith("9") and group != "00" and serial != "0000"


def entropy_ok(value: str) -> bool:
    """Reject low-entropy matches such as ``password=xxxxxxxx`` placeholders."""
    import math

    body = value.split("=", 1)[-1].split(":", 1)[-1].strip(" '\"")
    if len(body) < 8:
        return False
    counts = {c: body.count(c) for c in set(body)}
    ent = -sum((n / len(body)) * math.log2(n / len(body)) for n in counts.values())
    return ent >= 3.0


VALIDATORS: dict[str, Callable[[str], bool]] = {
    "none": lambda _v: True,
    "luhn": luhn,
    "iban": iban,
    "us_ssn": us_ssn,
    "entropy": entropy_ok,
}


@dataclass(frozen=True, slots=True)
class DlpPattern:
    id: str
    regex: re.Pattern[str]
    validator: str = "none"
    description: str = ""
    category: str = "secret"  # secret | pii | custom

    def find(self, text: str) -> Iterable[re.Match[str]]:
        check = VALIDATORS[self.validator]
        for m in self.regex.finditer(text):
            if check(m.group(0)):
                yield m


def _p(id_: str, rx: str, validator: str = "none", desc: str = "", cat: str = "secret", flags: int = 0) -> DlpPattern:
    return DlpPattern(id_, re.compile(rx, flags), validator, desc, cat)


BUILTIN_PATTERNS: dict[str, DlpPattern] = {
    p.id: p
    for p in [
        _p("aws_access_key", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b", desc="AWS access key id"),
        _p(
            "aws_secret_key",
            r"(?i)aws.{0,20}?(?:secret|key).{0,5}?['\"=:\s]{1,4}([A-Za-z0-9/+=]{40})\b",
            desc="AWS secret access key",
        ),
        _p("github_token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b"),
        _p("anthropic_key", r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}\b"),
        _p("openai_key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}\b"),
        _p("slack_token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
        _p("stripe_key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"),
        _p("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        _p("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        _p("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        _p("agentguard_key", r"\bag_(?:live|test)_[A-Za-z0-9]{32,}\b", desc="AgentGuard API key"),
        _p(
            "password_assignment",
            r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]?[^\s'\"]{8,}",
            validator="entropy",
        ),
        _p("credit_card", r"\b(?:\d[ -]?){12,18}\d\b", validator="luhn", cat="pii"),
        _p(
            "iban",
            r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b",
            validator="iban",
            cat="pii",
        ),
        _p("us_ssn", r"\b\d{3}-\d{2}-\d{4}\b", validator="us_ssn", cat="pii"),
        _p("email_address", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", cat="pii"),
        _p(
            "phone_number",
            r"(?<!\d)\+?\d{1,3}[ .\-]?\(?\d{2,4}\)?[ .\-]?\d{3,4}[ .\-]?\d{3,4}(?!\d)",
            cat="pii",
        ),
    ]
}

DEFAULT_SECRET_PATTERNS = tuple(k for k, v in BUILTIN_PATTERNS.items() if v.category == "secret")


def mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * min(len(value) - 4, 12)


class DlpScanner:
    def __init__(self, patterns: Mapping[str, DlpPattern] | None = None) -> None:
        self.patterns: dict[str, DlpPattern] = dict(BUILTIN_PATTERNS)
        if patterns:
            self.patterns.update(patterns)

    def add(self, pattern_id: str, regex: str, validator: str = "none", category: str = "custom") -> None:
        if validator not in VALIDATORS:
            raise ValueError(f"unknown validator {validator!r}")
        self.patterns[pattern_id] = DlpPattern(pattern_id, re.compile(regex), validator, category=category)

    def scan_text(self, text: str, pattern_ids: Iterable[str], arg_path: str = "$") -> list[DlpFinding]:
        findings = []
        for pid in pattern_ids:
            pattern = self.patterns.get(pid)
            if pattern is None:
                continue
            for m in pattern.find(text):
                findings.append(DlpFinding(pid, arg_path, mask(m.group(0)), m.start(), m.end()))
        return findings

    def scan_arguments(self, arguments: Mapping[str, Any], pattern_ids: Iterable[str]) -> list[DlpFinding]:
        ids = list(pattern_ids)
        out: list[DlpFinding] = []
        for path, value in flatten_arguments(arguments):
            out.extend(self.scan_text(value, ids, path))
        return out

    def redact_text(self, text: str, pattern_ids: Iterable[str]) -> str:
        spans = sorted(
            ((f.start, f.end, f.pattern_id) for f in self.scan_text(text, pattern_ids)),
            key=lambda s: (s[0], -s[1]),
        )
        out, pos = [], 0
        for start, end, pid in spans:
            if start < pos:
                continue
            out.append(text[pos:start])
            out.append(f"[REDACTED:{pid}]")
            pos = end
        out.append(text[pos:])
        return "".join(out)

    def redact_arguments(self, arguments: Any, pattern_ids: Iterable[str]) -> Any:
        ids = list(pattern_ids)
        if isinstance(arguments, Mapping):
            return {k: self.redact_arguments(v, ids) for k, v in arguments.items()}
        if isinstance(arguments, list):
            return [self.redact_arguments(v, ids) for v in arguments]
        if isinstance(arguments, str):
            return self.redact_text(arguments, ids)
        return arguments

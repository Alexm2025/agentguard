"""Destination allow/deny lists for emails, domains, URLs and file paths."""

from __future__ import annotations

import posixpath
import urllib.parse
from collections.abc import Callable
from fnmatch import fnmatchcase

from agentguard.core import entities
from agentguard.core.policy.model import DestinationRule

# Last path component names that conventionally select where data goes.
DEFAULT_DESTINATION_ARGS = frozenset(
    {
        "to", "cc", "bcc", "recipient", "recipients", "email", "emails", "address", "addresses",
        "url", "uri", "endpoint", "webhook", "webhook_url", "callback_url", "host", "hostname",
        "domain", "channel", "channel_id", "user", "username", "account", "account_id",
        "account_number", "iban", "destination", "dest", "target", "phone", "phone_number",
        "number", "path", "file_path", "filepath", "filename", "repo", "repository", "bucket",
        "remote", "payee", "beneficiary", "wallet", "wallet_address",
    }
)  # fmt: skip


def is_destination_path(path: str, extra: list[str]) -> bool:
    from agentguard.core.taint import path_matches

    if any(path_matches(sel, path) for sel in extra):
        return True
    parts = [p for p in path.split(".") if not p.isdigit()]
    return bool(parts) and parts[-1].lower() in DEFAULT_DESTINATION_ARGS


def _idna(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return host.lower()


def domain_matches(host: str, pattern: str) -> bool:
    host, pattern = _idna(host.strip(".")), pattern.lower().strip(".")
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return host == pattern or fnmatchcase(host, pattern)


def email_matches(address: str, pattern: str) -> bool:
    address, pattern = address.lower(), pattern.lower()
    if "@" in pattern:
        return fnmatchcase(address, pattern)
    return domain_matches(address.rsplit("@", 1)[-1], pattern)


def normalize_path(path: str) -> str:
    p = path.replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":  # windows drive
        p = "/" + p[0].lower() + p[2:]
    return posixpath.normpath(p)


def path_matches_pattern(path: str, pattern: str) -> bool:
    p = normalize_path(path)
    pat = normalize_path(pattern.rstrip("*")) if pattern.endswith(("/**", "/*")) else None
    if pat is not None:
        return p == pat or p.startswith(pat.rstrip("/") + "/")
    return fnmatchcase(p, normalize_path(pattern))


def _values(rule: DestinationRule, value: str) -> list[str]:
    if rule.kind == "email":
        found = entities.EMAIL.findall(value)
        return [e.lower() for e in found] or [value.strip()]
    if rule.kind in ("domain", "url"):
        host = entities.host_of(value.strip())
        return [host] if host else [value.strip()]
    return [value]


def check_destination(rule: DestinationRule, value: str) -> str | None:
    """Return a violation message, or ``None`` if ``value`` is permitted."""
    match: Callable[[str, str], bool]
    for v in _values(rule, value):
        if rule.kind == "email":
            if "@" not in v:
                return f"'{v[:80]}' is not a valid email address"
            match = email_matches
        elif rule.kind in ("domain", "url"):
            if rule.kind == "url":
                scheme = urllib.parse.urlsplit(value.strip()).scheme.lower()
                if scheme and scheme not in ("http", "https"):
                    return f"URL scheme '{scheme}' is not allowed"
            match = domain_matches
        elif rule.kind == "path":
            match = path_matches_pattern
        else:
            match = fnmatchcase
        if any(match(v, pat) for pat in rule.deny):
            return f"{rule.kind} '{v[:120]}' is on the deny list for '{rule.arg}'"
        if rule.allow and not any(match(v, pat) for pat in rule.allow):
            return f"{rule.kind} '{v[:120]}' is not on the allow list for '{rule.arg}'"
    return None

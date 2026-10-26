"""Extraction of high-signal entities (emails, URLs, domains, IPs, paths, account numbers).

Injected instructions usually smuggle a *destination* (an attacker address or URL) or an
*identifier* (an account number) into a tool call. Matching these exactly is much more robust
than matching free text.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from functools import lru_cache

from agentguard.core.normalize import normalize

EMAIL = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,63}", re.I)
URL = re.compile(r"\b(?:https?|ftp|wss?)://[^\s<>\"'`)\]]+", re.I)
DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b", re.I)
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
PATH = re.compile(r"(?:(?<=\s)|^)(?:~|\.{1,2})?(?:/[\w.\-]+){2,}/?|[a-z]:\\(?:[\w.\- ]+\\?)+", re.I)
NUMBER = re.compile(r"(?<!\w)(?<!\d\.)\d(?:[\d \-]{4,30}\d)(?!\w)(?!\.\d)")

# Domains that appear in almost every document and carry no attribution signal.
_COMMON_TLD_WORDS = frozenset({"e.g", "i.e", "etc.", "a.m", "p.m"})
_FILE_EXTS = frozenset(
    {"txt", "md", "py", "js", "ts", "json", "yaml", "yml", "csv", "pdf", "png", "jpg", "html", "xml", "log"}
)


@dataclass(frozen=True, slots=True)
class Entity:
    kind: str  # email | url | domain | ip | path | number
    value: str


def _clean_url(url: str) -> str:
    return url.rstrip(".,;:!?")


def host_of(url: str) -> str | None:
    try:
        parsed = urllib.parse.urlsplit(url if "://" in url else f"http://{url}")
    except ValueError:
        return None
    return parsed.hostname.lower().rstrip(".") if parsed.hostname else None


def registrable_domain(host: str) -> str:
    """Approximate eTLD+1 (last two labels, three for common second-level ccTLD suffixes)."""
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and labels[-2] in {"co", "com", "org", "net", "ac", "gov", "edu"} and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


@lru_cache(maxsize=4096)
def extract(text: str) -> frozenset[Entity]:
    norm = normalize(text)
    out: set[Entity] = set()
    for m in EMAIL.finditer(norm):
        email = m.group(0).strip(".")
        out.add(Entity("email", email))
        out.add(Entity("domain", email.rsplit("@", 1)[1]))
    for m in URL.finditer(norm):
        url = _clean_url(m.group(0))
        out.add(Entity("url", url))
        host = host_of(url)
        if host:
            out.add(Entity("domain", host))
    for m in DOMAIN.finditer(norm):
        dom = m.group(0).strip(".")
        tld = dom.rsplit(".", 1)[-1]
        if dom in _COMMON_TLD_WORDS or tld in _FILE_EXTS or tld.isdigit():
            continue
        if f"@{dom}" in norm and not any(e.kind == "domain" and e.value == dom for e in out):
            continue
        out.add(Entity("domain", dom))
    for m in IPV4.finditer(norm):
        out.add(Entity("ip", m.group(0)))
    for m in PATH.finditer(text):
        out.add(Entity("path", m.group(0).strip()))
    for m in NUMBER.finditer(norm):
        digits = re.sub(r"\D", "", m.group(0))
        if 6 <= len(digits) <= 30:
            out.add(Entity("number", digits))
    return frozenset(out)


def emails(text: str) -> list[str]:
    return sorted(e.value for e in extract(text) if e.kind == "email")


def urls(text: str) -> list[str]:
    return sorted(e.value for e in extract(text) if e.kind == "url")


def domains(text: str) -> list[str]:
    return sorted(e.value for e in extract(text) if e.kind == "domain")

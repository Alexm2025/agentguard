"""SIEM forwarding: syslog (RFC 5424) with CEF payloads, and signed JSON webhooks.

Environment:
  AGENTGUARD_SIEM_SYSLOG          udp://host:514 | tcp://host:514 | tls://host:6514
  AGENTGUARD_SIEM_SYSLOG_CA       CA bundle for tls:// (optional; system store otherwise)
  AGENTGUARD_SIEM_WEBHOOK_URL     https://siem.example.com/ingest
  AGENTGUARD_SIEM_WEBHOOK_SECRET  HMAC secret; requests carry x-agentguard-signature
  AGENTGUARD_SIEM_MIN_ACTION      only forward tool events at or above this action (default ALLOW = everything)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import ssl
import urllib.parse
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import httpx

from agentguard import __version__
from agentguard.core.types import Action
from agentguard.server.security import hmac_signature

log = logging.getLogger("agentguard.ee.siem")
Forwarder = Callable[[str, list[dict[str, Any]]], Awaitable[None]]

_SEVERITY = {"ALLOW": 2, "REDACT": 5, "REQUIRE_APPROVAL": 6, "BLOCK": 8}


def _cef_escape_header(v: str) -> str:
    return v.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _cef_escape_ext(v: str) -> str:
    return v.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "\\r")


def to_cef(org_id: str, ev: dict[str, Any]) -> str:
    action = str(ev.get("action") or "")
    sig = f"{ev.get('type', 'event')}:{action or 'INFO'}"
    name = f"{ev.get('type', 'event')} {ev.get('tool') or ''} {action}".strip()
    ext = {
        "rt": str(int(datetime.fromisoformat(str(ev.get("timestamp")).replace("Z", "+00:00")).timestamp() * 1000))
        if ev.get("timestamp")
        else "",
        "act": action,
        "cs1Label": "org",
        "cs1": org_id,
        "cs2Label": "tool",
        "cs2": str(ev.get("tool") or ""),
        "cs3Label": "session",
        "cs3": str(ev.get("session_id") or ""),
        "cs4Label": "taint_chain",
        "cs4": "; ".join(ev.get("taint_chain") or [])[:1000],
        "cs5Label": "reasons",
        "cs5": "; ".join(r.get("message", "") for r in ev.get("reasons") or [])[:1000],
        "cs6Label": "source",
        "cs6": str(ev.get("source") or ""),
        "externalId": str(ev.get("id") or ""),
    }
    ext_s = " ".join(f"{k}={_cef_escape_ext(v)}" for k, v in ext.items() if v != "")
    return (
        "|".join(
            [
                "CEF:0",
                "AgentGuard",
                "AgentGuard",
                __version__,
                _cef_escape_header(sig),
                _cef_escape_header(name),
                str(_SEVERITY.get(action, 3)),
            ]
        )
        + "|"
        + ext_s
    )


def to_syslog(cef: str, severity: int) -> bytes:
    pri = 8 * 13 + min(7, max(0, 8 - severity))  # facility 13 (log audit), map CEF severity to syslog severity
    ts = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    host = socket.gethostname()[:255] or "-"
    return f"<{pri}>1 {ts} {host} agentguard - - - {cef}".encode()


class SyslogForwarder:
    def __init__(self, url: str, ca_file: str | None = None, min_action: str = "ALLOW") -> None:
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("udp", "tcp", "tls") or not u.hostname:
            raise ValueError("syslog URL must be udp://, tcp:// or tls://host:port")
        self.scheme, self.host, self.port = (
            u.scheme,
            u.hostname,
            u.port or (6514 if u.scheme == "tls" else 514),
        )
        self.ca_file = ca_file
        self.min_sev = Action(min_action).severity

    def _send_sync(self, frames: list[bytes]) -> None:
        if self.scheme == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                for f in frames:
                    s.sendto(f, (self.host, self.port))
            return
        raw = socket.create_connection((self.host, self.port), timeout=5)
        conn: socket.socket = raw
        if self.scheme == "tls":
            ctx = ssl.create_default_context(cafile=self.ca_file)
            conn = ctx.wrap_socket(raw, server_hostname=self.host)
        with conn:
            for f in frames:  # RFC 6587 octet counting
                conn.sendall(str(len(f)).encode() + b" " + f)

    async def __call__(self, org_id: str, events: list[dict[str, Any]]) -> None:
        frames = []
        for ev in events:
            action = ev.get("action")
            if action and Action(action).severity < self.min_sev:
                continue
            frames.append(to_syslog(to_cef(org_id, ev), _SEVERITY.get(str(action), 3)))
        if frames:
            await asyncio.to_thread(self._send_sync, frames)


class WebhookForwarder:
    def __init__(
        self, url: str, secret: str, client: httpx.AsyncClient | None = None, min_action: str = "ALLOW"
    ) -> None:
        if (
            not url.startswith("https://")
            and not url.startswith("http://127.0.0.1")
            and not url.startswith("http://localhost")
        ):
            raise ValueError("SIEM webhook URL must use https")
        self.url, self.secret = url, secret
        self.client = client or httpx.AsyncClient(timeout=10)
        self.min_sev = Action(min_action).severity

    async def __call__(self, org_id: str, events: list[dict[str, Any]]) -> None:
        events = [e for e in events if not e.get("action") or Action(e["action"]).severity >= self.min_sev]
        if not events:
            return
        body = json.dumps({"org_id": org_id, "events": events}, default=str).encode()
        ts = str(int(datetime.now(UTC).timestamp()))
        r = await self.client.post(
            self.url,
            content=body,
            headers={
                "content-type": "application/json",
                "x-agentguard-timestamp": ts,
                "x-agentguard-signature": hmac_signature(self.secret, body, ts),
            },
        )
        if r.status_code >= 300:
            log.warning("SIEM webhook returned %s", r.status_code)


def forwarders_from_env() -> list[Forwarder]:
    out: list[Forwarder] = []
    min_action = os.environ.get("AGENTGUARD_SIEM_MIN_ACTION", "ALLOW")
    if url := os.environ.get("AGENTGUARD_SIEM_SYSLOG"):
        out.append(SyslogForwarder(url, os.environ.get("AGENTGUARD_SIEM_SYSLOG_CA"), min_action))
    if url := os.environ.get("AGENTGUARD_SIEM_WEBHOOK_URL"):
        secret = os.environ.get("AGENTGUARD_SIEM_WEBHOOK_SECRET")
        if not secret:
            raise ValueError("AGENTGUARD_SIEM_WEBHOOK_SECRET is required with AGENTGUARD_SIEM_WEBHOOK_URL")
        out.append(WebhookForwarder(url, secret, min_action=min_action))
    return out

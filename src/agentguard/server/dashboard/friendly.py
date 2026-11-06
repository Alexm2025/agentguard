"""Plain-English descriptions of events for people who are not security engineers.

Turns raw decision events into a short headline, a one-sentence explanation, an icon and a tone,
e.g. "Stopped an email to collector@exfil.example" / "That address came from a web page
(trails.example), not from you."
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

STATUS = {
    "BLOCK": ("Stopped", "danger"),
    "REQUIRE_APPROVAL": ("Waiting for you", "warn"),
    "REDACT": ("Data hidden", "info"),
    "ALLOW": ("Allowed", "ok"),
}

# (keyword in tool name, icon, verb phrase used in sentences)
_TOOL_KINDS: list[tuple[tuple[str, ...], str, str]] = [
    (("email", "mail", "inbox"), "mail", "send an email"),
    (("money", "transfer", "pay", "transaction", "iban", "invoice", "refund"), "money", "move money"),
    (("delete", "remove", "drop", "wipe", "cancel"), "trash", "delete something"),
    (("shell", "exec", "run_", "command", "sql"), "terminal", "run a command"),
    (("calendar", "event", "meeting", "schedule"), "calendar", "change your calendar"),
    (("slack", "message", "chat", "channel", "post", "dm"), "chat", "send a message"),
    (("web", "url", "fetch", "browse", "http", "search", "page"), "globe", "use the web"),
    (("file", "document", "doc", "drive", "upload", "share", "write", "read_file"), "file", "use a file"),
    (("user", "invite", "member", "account", "password"), "user", "change an account"),
    (("weather", "get_", "list_", "read_", "search"), "eye", "look something up"),
]
_SOURCE_KINDS: list[tuple[tuple[str, ...], str]] = [
    (("web", "url", "fetch", "browse", "http", "page"), "a web page"),
    (("search",), "search results"),
    (("email", "mail", "inbox"), "an email"),
    (("file", "document", "doc", "drive"), "a file"),
    (("slack", "message", "channel", "chat"), "a chat message"),
    (("calendar", "event"), "a calendar event"),
    (("issue", "ticket", "github", "repo"), "an issue or ticket"),
    (("review", "rating"), "online reviews"),
]
_SECRETS = {
    "aws_access_key": "an AWS key",
    "aws_secret_key": "an AWS secret key",
    "github_token": "a GitHub token",
    "openai_key": "an OpenAI key",
    "anthropic_key": "an Anthropic key",
    "slack_token": "a Slack token",
    "stripe_key": "a Stripe key",
    "google_api_key": "a Google API key",
    "private_key": "a private key",
    "jwt": "a login token",
    "agentguard_key": "an AgentGuard key",
    "password_assignment": "a password",
    "credit_card": "a card number",
    "iban": "a bank account number",
    "us_ssn": "a social security number",
    "email_address": "an email address",
    "phone_number": "a phone number",
}


def tool_label(name: str | None) -> str:
    if not name:
        return "A tool"
    words = re.sub(r"[_\-.]+", " ", name).strip()
    return words[:1].upper() + words[1:]


def tool_kind(name: str | None) -> tuple[str, str]:
    n = (name or "").lower()
    for keys, icon, verb in _TOOL_KINDS:
        if any(k in n for k in keys):
            return icon, verb
    return "tool", f"use {tool_label(name).lower()}"


def source_phrase(label: str | None) -> str:
    """'read_web(url=https://trails.example/x)' -> 'a web page (trails.example)'."""
    if not label:
        return "another tool's output"
    tool = label.split("(", 1)[0].lower()
    phrase = next(
        (p for keys, p in _SOURCE_KINDS if any(k in tool for k in keys)), f"the {tool_label(tool).lower()} tool"
    )
    m = re.search(r"https?://[^\s,)]+", label)
    if m:
        host = urllib.parse.urlsplit(m.group(0)).hostname
        if host:
            return f"{phrase} ({host})"
    return phrase


def _short(value: Any, n: int = 60) -> str:
    s = str(value)
    return s if len(s) <= n else s[: n - 1] + "…"


def describe(event_type: str, tool: str | None, action: str | None, data: dict[str, Any]) -> dict[str, str]:
    """Return {headline, detail, icon, tone, status} for an event."""
    icon, verb = tool_kind(tool)
    status, tone = STATUS.get(action or "", ("Info", "info"))
    label = tool_label(tool)
    reasons = data.get("reasons") or []
    codes = {r.get("code") for r in reasons}
    rule_ids = {r.get("rule_id") for r in reasons if r.get("rule_id")}
    matches = [m for m in data.get("taint_matches") or [] if not m.get("also_in_trusted")]
    dlp = data.get("dlp") or []

    if event_type == "tool_result":
        src = source_phrase(data.get("source_ref") or tool)
        flagged = any(d.get("flagged") for d in data.get("detections") or [])
        if action in ("BLOCK", "REDACT"):
            return {
                "headline": f"Hid a suspicious result from {src}",
                "icon": "shield",
                "tone": "danger" if action == "BLOCK" else "info",
                "detail": "It contained hidden instructions aimed at your agent, so AgentGuard kept them away from it.",
                "status": "Hidden",
            }
        if flagged:
            return {
                "headline": f"Your agent read {src}",
                "icon": "eye",
                "tone": "warn",
                "status": "Watching",
                "detail": "It seems to contain hidden instructions. AgentGuard is watching what the agent does next.",
            }
        return {
            "headline": f"Your agent read {src}",
            "icon": "eye",
            "tone": "neutral",
            "status": "Read",
            "detail": "Content from outside is treated as untrusted.",
        }
    if event_type == "mcp_tool_quarantined":
        return {
            "headline": f"Removed an unsafe tool: {label}",
            "icon": "shield",
            "tone": "danger",
            "status": "Removed",
            "detail": "Its description contained hidden instructions or changed after it was approved.",
        }
    if event_type == "approval_resolved":
        st = str(data.get("status", "")).lower()
        return {
            "headline": f"{label}: {'allowed' if st == 'approved' else 'not allowed'} by a person",
            "icon": "user",
            "tone": "ok" if st == "approved" else "danger",
            "status": st.capitalize() or "Decided",
            "detail": "",
        }

    # Tool calls
    if action == "BLOCK":
        headline = f"Stopped your agent from trying to {verb}"
    elif action == "REQUIRE_APPROVAL":
        headline = f"Your agent wants to {verb}"
    elif action == "REDACT":
        headline = f"Your agent used “{label}” - private data was hidden first"
    else:
        headline = f"Your agent used “{label}”"

    detail = ""
    if matches:
        m = matches[0]
        detail = (
            f"It wanted to use “{_short(m.get('evidence'))}”, which came from {source_phrase(m.get('source'))}, "
            "not from you."
        )
    elif dlp:
        what = _SECRETS.get(str(dlp[0].get("pattern")), "private data")
        detail = f"It included {what}, which should never leave your system."
    elif any(rid and rid.startswith("injection-steered") for rid in rule_ids):
        detail = "It just read something with hidden instructions, so this action is risky."
    elif "TOOL_ACTION" in codes:
        detail = (
            "Your rules say this action always needs a person's OK."
            if action == "REQUIRE_APPROVAL"
            else "Your rules never allow this action."
        )
    elif "RATE_LIMIT" in codes:
        detail = "It did this too many times in a short period."
    elif "DESTINATION" in codes:
        detail = "The destination is not on your list of allowed places."
    elif "JUDGE" in codes:
        detail = "A second AI check thought this did not match what you asked for."
    elif "ENGINE_ERROR" in codes:
        detail = "AgentGuard couldn't check it, so it played safe."
    elif "DENIED" in codes:
        detail = "A person said no."
    elif "APPROVED" in codes:
        detail = "A person said yes."
    elif reasons:
        detail = str(reasons[0].get("message", "")).capitalize() + "."
    elif action == "ALLOW":
        detail = "Nothing looked wrong."
    return {"headline": headline, "detail": detail, "icon": icon, "tone": tone, "status": status}


def describe_event(e: Any) -> dict[str, str]:
    return describe(e.type, e.tool, e.action, e.data or {})


def describe_approval(tool: str, data: dict[str, Any]) -> dict[str, str]:
    return describe("tool_call", tool, "REQUIRE_APPROVAL", data or {})


def story(e: Any) -> list[dict[str, str]]:
    """Step-by-step account of a blocked or held call, for the detail page."""
    d = e.data or {}
    matches = [m for m in d.get("taint_matches") or [] if not m.get("also_in_trusted")]
    icon, verb = tool_kind(e.tool)
    steps: list[dict[str, str]] = []
    if matches:
        src = source_phrase(matches[0].get("source"))
        steps.append({"icon": "eye", "tone": "neutral", "text": f"Your agent read {src}."})
        if any(dt.get("flagged") for dt in d.get("detections") or []):
            steps.append(
                {
                    "icon": "alert",
                    "tone": "warn",
                    "text": "That content contained hidden instructions meant for the agent.",
                }
            )
        steps.append(
            {
                "icon": icon,
                "tone": "warn",
                "text": f"Then it tried to {verb} using “{_short(matches[0].get('evidence'))}”, from that content.",
            }
        )
    elif d.get("dlp"):
        what = _SECRETS.get(str(d["dlp"][0].get("pattern")), "private data")
        steps.append({"icon": icon, "tone": "warn", "text": f"Your agent tried to {verb} that included {what}."})
    else:
        steps.append({"icon": icon, "tone": "warn", "text": f"Your agent tried to {verb}."})
    final = {
        "BLOCK": ("shield", "danger", "AgentGuard stopped it. Nothing was sent or changed."),
        "REQUIRE_APPROVAL": ("hand", "warn", "AgentGuard paused it and asked a person to decide."),
        "REDACT": ("shield", "info", "AgentGuard hid the private data and let it continue."),
        "ALLOW": ("check", "ok", "AgentGuard allowed it."),
    }.get(e.action or "", ("shield", "info", "AgentGuard recorded it."))
    steps.append({"icon": final[0], "tone": final[1], "text": final[2]})
    return steps

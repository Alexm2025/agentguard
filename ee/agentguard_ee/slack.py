"""Slack interactive approvals.

Environment:
  AGENTGUARD_SLACK_BOT_TOKEN       xoxb-... (chat:write)
  AGENTGUARD_SLACK_SIGNING_SECRET  verifies interaction requests
  AGENTGUARD_SLACK_CHANNEL         channel id for approval requests
  AGENTGUARD_SLACK_APPROVER_IDS    comma-separated Slack user ids allowed to approve/deny (required)

Configure the Slack app's Interactivity request URL as
``{AGENTGUARD_PUBLIC_URL}/api/v1/ee/slack/interactions``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.server import services
from agentguard.server.auth import get_db
from agentguard.server.models import Approval, Organization
from agentguard.server.settings import ServerSettings

router = APIRouter(prefix="/api/v1/ee/slack")
MAX_SKEW = 300


@dataclass
class SlackConfig:
    bot_token: str
    signing_secret: str
    channel: str
    approver_ids: frozenset[str]
    api_base: str = "https://slack.com/api"

    @classmethod
    def from_env(cls) -> SlackConfig | None:
        token = os.environ.get("AGENTGUARD_SLACK_BOT_TOKEN")
        if not token:
            return None
        secret = os.environ.get("AGENTGUARD_SLACK_SIGNING_SECRET")
        channel = os.environ.get("AGENTGUARD_SLACK_CHANNEL")
        approvers = frozenset(
            x.strip() for x in os.environ.get("AGENTGUARD_SLACK_APPROVER_IDS", "").split(",") if x.strip()
        )
        if not secret or not channel or not approvers:
            raise ValueError("Slack approvals need AGENTGUARD_SLACK_SIGNING_SECRET, _CHANNEL and _APPROVER_IDS")
        return cls(
            token,
            secret,
            channel,
            approvers,
            os.environ.get("AGENTGUARD_SLACK_API_BASE", "https://slack.com/api"),
        )


def verify_signature(secret: str, timestamp: str, body: bytes, signature: str, now: float | None = None) -> bool:
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs((now or time.time()) - ts) > MAX_SKEW:
        return False
    base = b"v0:" + timestamp.encode() + b":" + body
    expected = "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def blocks_for(apr: Approval, settings: ServerSettings, resolved: str | None = None) -> list[dict[str, Any]]:
    d = services.approval_dict(apr)
    reasons = "\n".join(f"• {r.get('message', '')}" for r in (d.get("reasons") or [])[:5])
    chain = "\n".join(f"`{c}`" for c in (d.get("taint_chain") or [])[:3])
    args = json.dumps(d.get("arguments"), ensure_ascii=False)[:1500]
    blocks: list[dict[str, Any]] = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*AgentGuard approval required:* `{apr.tool}` (risk {d.get('risk')})",
            },
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"{reasons or 'policy requires approval'}\n{chain}"},
        },
        {"type": "section", "text": {"type": "mrkdwn", "text": f"```{args}```"}},
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"<{settings.public_url.rstrip('/')}/approvals/{apr.id}|Open in AgentGuard> · expires {d['expires_at'][:19]}",  # noqa: E501
                }
            ],
        },
    ]
    if resolved:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": resolved}})
    else:
        blocks.append(
            {
                "type": "actions",
                "block_id": f"agentguard:{apr.id}",
                "elements": [
                    {
                        "type": "button",
                        "style": "primary",
                        "text": {"type": "plain_text", "text": "Approve"},
                        "action_id": "approve",
                        "value": apr.id,
                    },
                    {
                        "type": "button",
                        "style": "danger",
                        "text": {"type": "plain_text", "text": "Deny"},
                        "action_id": "deny",
                        "value": apr.id,
                    },
                ],
            }
        )
    return blocks


async def notifier(
    apr: Approval,
    org: Organization,
    settings: ServerSettings,
    *,
    cfg: SlackConfig | None = None,
    client: httpx.AsyncClient | None = None,
) -> None:
    cfg = cfg or SlackConfig.from_env()
    if cfg is None:
        return
    async with client or httpx.AsyncClient(timeout=10) as c:
        r = await c.post(
            f"{cfg.api_base}/chat.postMessage",
            headers={"authorization": f"Bearer {cfg.bot_token}"},
            json={
                "channel": cfg.channel,
                "text": f"AgentGuard approval required: {apr.tool}",
                "blocks": blocks_for(apr, settings),
            },
        )
        data = r.json()
        if not data.get("ok"):
            raise RuntimeError(f"Slack chat.postMessage failed: {data.get('error')}")


@router.post("/interactions")
async def interactions(request: Request, db: AsyncSession = Depends(get_db)) -> JSONResponse:
    cfg: SlackConfig = request.app.state.slack
    body = await request.body()
    if not verify_signature(
        cfg.signing_secret,
        request.headers.get("x-slack-request-timestamp", ""),
        body,
        request.headers.get("x-slack-signature", ""),
    ):
        raise HTTPException(status_code=401, detail="invalid Slack signature")
    form = urllib.parse.parse_qs(body.decode())
    payload = json.loads(form.get("payload", ["{}"])[0])
    user = (payload.get("user") or {}).get("id", "")
    actions = payload.get("actions") or []
    if not actions:
        return JSONResponse({"ok": True})
    act = actions[0]
    if act.get("action_id") not in ("approve", "deny"):
        return JSONResponse({"ok": True})
    apr = await db.get(Approval, str(act.get("value")))
    if apr is None:
        return JSONResponse({"response_type": "ephemeral", "text": "Approval not found."})
    if user not in cfg.approver_ids:
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "replace_original": False,
                "text": "You are not authorised to resolve AgentGuard approvals.",
            }
        )
    try:
        await services.resolve_approval(db, apr, act["action_id"], f"slack:{user}", "", "slack")
    except ValueError as exc:
        return JSONResponse({"response_type": "ephemeral", "replace_original": False, "text": str(exc)})
    verdict = "approved" if apr.status == "approved" else "denied"
    return JSONResponse(
        {
            "replace_original": True,
            "text": f"{apr.tool}: {verdict}",
            "blocks": blocks_for(apr, request.app.state.settings, f"*{verdict.title()}* by <@{user}>"),
        }
    )

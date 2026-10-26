"""Business logic shared by the REST API and the dashboard."""

from __future__ import annotations

import json
import logging
import statistics
from collections import Counter
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.core.events import scrub
from agentguard.core.policy.loader import parse_policy, policy_digest, validate_policy_data
from agentguard.server import audit
from agentguard.server.models import (
    Approval,
    Event,
    FalsePositiveReport,
    Organization,
    Policy,
    PolicyVersion,
    utcnow,
)
from agentguard.server.security import hmac_signature, sign
from agentguard.server.settings import ServerSettings

log = logging.getLogger(__name__)

EVENT_TYPES = {"tool_call", "tool_result", "approval_resolved", "mcp_tool_quarantined", "detection", "custom"}
Notifier = Callable[[Approval, Organization, ServerSettings], Awaitable[None]]
Forwarder = Callable[[str, list[dict[str, Any]]], Awaitable[None]]


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            pass
    return utcnow()


async def ingest_events(
    db: AsyncSession,
    org_id: str,
    project_id: str | None,
    events: Sequence[dict[str, Any]],
    forwarders: Sequence[Forwarder] = (),
) -> int:
    """Store events. The tenant always comes from the authenticated principal, never the payload."""
    stored = []
    seen_ids: set[str] = set()
    for raw in events:
        if not isinstance(raw, dict):
            continue  # type: ignore[unreachable]  # untrusted JSON may contain non-objects
        ev = scrub(raw)  # defence in depth: clients should already have scrubbed
        eid = str(ev.get("id") or "")[:64]
        if not eid or eid in seen_ids:
            continue
        seen_ids.add(eid)
        etype = str(ev.get("type", "custom"))
        if etype not in EVENT_TYPES:
            etype = "custom"
        ev["tenant_id"] = org_id
        pid = project_id or (str(ev["project_id"])[:40] if ev.get("project_id") else None)
        ev["project_id"] = pid
        existing = await db.get(Event, eid)
        if existing is not None:
            if existing.org_id != org_id:
                continue  # never let one tenant overwrite another's event id
            continue
        row = Event(
            id=eid,
            org_id=org_id,
            project_id=pid,
            session_id=(str(ev.get("session_id"))[:128] if ev.get("session_id") else None),
            type=etype,
            source=str(ev.get("source", "sdk"))[:40],
            tool=(str(ev["tool"])[:200] if ev.get("tool") else None),
            action=(str(ev["action"])[:20] if ev.get("action") else None),
            risk=(str(ev["risk"])[:20] if ev.get("risk") else None),
            latency_ms=float(ev["latency_ms"]) if isinstance(ev.get("latency_ms"), int | float) else None,
            timestamp=_parse_ts(ev.get("timestamp")),
            data=json.loads(json.dumps(ev, default=str)),
        )
        db.add(row)
        stored.append(row.data)
    await db.commit()
    for fwd in forwarders:
        try:
            await fwd(org_id, stored)
        except Exception:
            log.exception("event forwarder failed")
    return len(stored)


# ---------------------------------------------------------------- approvals


async def create_approval(
    db: AsyncSession,
    org: Organization,
    project_id: str | None,
    event: dict[str, Any],
    timeout_seconds: float,
    settings: ServerSettings,
    notifiers: Sequence[Notifier],
) -> Approval:
    data = scrub(event)
    timeout = max(10.0, min(float(timeout_seconds), 86_400.0))
    apr = Approval(
        org_id=org.id,
        project_id=project_id or data.get("project_id"),
        event_id=str(data.get("id", ""))[:64],
        tool=str(data.get("tool", "?"))[:200],
        data=json.loads(json.dumps(data, default=str)),
        expires_at=utcnow() + timedelta(seconds=timeout),
    )
    db.add(apr)
    await db.commit()
    await ingest_events(db, org.id, apr.project_id, [{**data, "approval_id": apr.id}])
    for n in notifiers:
        try:
            await n(apr, org, settings)
        except Exception:
            log.exception("approval notifier failed")
    return apr


def effective_status(apr: Approval) -> str:
    exp = apr.expires_at if apr.expires_at.tzinfo else apr.expires_at.replace(tzinfo=UTC)
    if apr.status == "pending" and exp < utcnow():
        return "expired"
    return apr.status


async def resolve_approval(
    db: AsyncSession, apr: Approval, decision: str, actor: str, note: str, channel: str
) -> Approval:
    if decision not in ("approve", "deny"):
        raise ValueError("decision must be approve or deny")
    st = effective_status(apr)
    if st != "pending":
        raise ValueError(f"approval is already {st}")
    apr.status = "approved" if decision == "approve" else "denied"
    apr.resolved_by = actor[:200]
    apr.resolved_at = utcnow()
    apr.resolution_note = note[:1000]
    apr.channel = channel
    await db.commit()
    await audit.append(
        db,
        apr.org_id,
        actor,
        f"approval.{apr.status}",
        apr.id,
        {"tool": apr.tool, "event_id": apr.event_id, "channel": channel, "note": note[:200]},
    )
    return apr


def approval_links(apr: Approval, settings: ServerSettings) -> dict[str, str]:
    ttl = 7 * 24 * 3600
    base = settings.public_url.rstrip("/")
    return {
        "dashboard": f"{base}/approvals/{apr.id}",
        "approve_token": sign({"apr": apr.id, "org": apr.org_id, "d": "approve"}, settings.secret_key, ttl),
        "deny_token": sign({"apr": apr.id, "org": apr.org_id, "d": "deny"}, settings.secret_key, ttl),
        "resolve_url": f"{base}/api/v1/approvals/{apr.id}/webhook-resolve",
    }


async def webhook_notifier(apr: Approval, org: Organization, settings: ServerSettings) -> None:
    """POST ``approval.created`` to the org's approval webhook, signed with the org's secret.

    The receiver approves/denies by POSTing ``{"token": <approve_token|deny_token>}`` to
    ``resolve_url``. Tokens are single-purpose HMAC-signed and expire after 7 days.
    """
    cfg = (org.settings or {}).get("approval_webhook") or {}
    url, secret = cfg.get("url"), cfg.get("secret")
    if not url or not secret:
        return
    body = json.dumps(
        {"type": "approval.created", "approval": approval_dict(apr), "links": approval_links(apr, settings)}
    ).encode()
    ts = str(int(utcnow().timestamp()))
    async with httpx.AsyncClient(timeout=10) as client:
        await client.post(
            url,
            content=body,
            headers={
                "content-type": "application/json",
                "x-agentguard-timestamp": ts,
                "x-agentguard-signature": hmac_signature(secret, body, ts),
            },
        )


def approval_dict(apr: Approval) -> dict[str, Any]:
    return {
        "id": apr.id,
        "status": effective_status(apr),
        "tool": apr.tool,
        "event_id": apr.event_id,
        "project_id": apr.project_id,
        "arguments": apr.data.get("arguments"),
        "reasons": apr.data.get("reasons"),
        "taint_chain": apr.data.get("taint_chain"),
        "risk": apr.data.get("risk"),
        "created_at": apr.created_at.isoformat(),
        "expires_at": apr.expires_at.isoformat(),
        "resolved_by": apr.resolved_by,
        "resolved_at": apr.resolved_at.isoformat() if apr.resolved_at else None,
        "resolution_note": apr.resolution_note,
        "channel": apr.channel,
    }


# ---------------------------------------------------------------- policies


async def create_policy_version(
    db: AsyncSession, policy: Policy, yaml_text: str, actor: str, comment: str = "", activate: bool = True
) -> PolicyVersion:
    import yaml as _yaml

    try:
        data = _yaml.safe_load(yaml_text) or {}
    except _yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc
    errors = validate_policy_data(data)
    if errors:
        raise ValueError("; ".join(errors[:20]))
    last = (
        await db.execute(select(func.max(PolicyVersion.revision)).where(PolicyVersion.policy_id == policy.id))
    ).scalar()
    revision = int(last or 0) + 1
    data["revision"] = revision
    data.setdefault("name", policy.name)
    text = _yaml.safe_dump(data, sort_keys=False)
    parsed = parse_policy(text)
    pv = PolicyVersion(
        policy_id=policy.id,
        org_id=policy.org_id,
        revision=revision,
        yaml=text,
        digest=policy_digest(parsed),
        comment=comment[:500],
        created_by=actor[:40],
    )
    db.add(pv)
    if activate:
        policy.active_revision = revision
    await db.commit()
    await audit.append(
        db,
        policy.org_id,
        actor,
        "policy.version_created",
        policy.id,
        {"name": policy.name, "revision": revision, "activated": activate, "digest": pv.digest},
    )
    return pv


async def active_policy(db: AsyncSession, org_id: str, project_id: str | None) -> tuple[Policy, PolicyVersion] | None:
    q = select(Policy).where(Policy.org_id == org_id, Policy.active_revision.is_not(None))
    candidates = (await db.execute(q.order_by(Policy.created_at.desc()))).scalars().all()
    chosen = next((p for p in candidates if project_id and p.project_id == project_id), None) or next(
        (p for p in candidates if p.project_id is None), None
    )
    if chosen is None:
        return None
    pv = (
        await db.execute(
            select(PolicyVersion).where(
                PolicyVersion.policy_id == chosen.id, PolicyVersion.revision == chosen.active_revision
            )
        )
    ).scalar_one()
    return chosen, pv


# ---------------------------------------------------------------- metrics


async def metrics_summary(db: AsyncSession, org_id: str, hours: int = 24) -> dict[str, Any]:
    since = utcnow() - timedelta(hours=hours)
    rows = (
        await db.execute(
            select(Event.action, Event.latency_ms, Event.type)
            .where(Event.org_id == org_id, Event.timestamp >= since)
            .order_by(Event.timestamp.desc())
            .limit(50_000)
        )
    ).all()
    calls = [r for r in rows if r.type == "tool_call"]
    actions = Counter(r.action for r in calls)
    latencies = sorted(r.latency_ms for r in calls if r.latency_ms is not None)
    apr_rows = (
        await db.execute(
            select(Approval.status, func.count())
            .where(Approval.org_id == org_id, Approval.created_at >= since)
            .group_by(Approval.status)
        )
    ).all()
    apr = {s: int(c) for s, c in apr_rows}
    resolved = apr.get("approved", 0) + apr.get("denied", 0)
    fps = int(
        (
            await db.execute(
                select(func.count())
                .select_from(FalsePositiveReport)
                .where(FalsePositiveReport.org_id == org_id, FalsePositiveReport.created_at >= since)
            )
        ).scalar()
        or 0
    )
    blocked = actions.get("BLOCK", 0)

    def pct(p: float) -> float | None:
        if not latencies:
            return None
        return round(float(latencies[min(len(latencies) - 1, int(p * len(latencies)))]), 3)

    return {
        "window_hours": hours,
        "tool_calls": len(calls),
        "actions": dict(actions),
        "attacks_blocked": blocked,
        "approvals": apr,
        "approval_rate": round(apr.get("approved", 0) / resolved, 4) if resolved else None,
        "false_positive_reports": fps,
        "false_positive_rate": round(fps / blocked, 4) if blocked else None,
        "latency_ms": {
            "p50": pct(0.5),
            "p95": pct(0.95),
            "p99": pct(0.99),
            "mean": round(statistics.fmean(latencies), 3) if latencies else None,
        },
        "tool_results_flagged": sum(1 for r in rows if r.type == "tool_result" and r.action in ("BLOCK", "REDACT")),
    }


async def prune_events(db: AsyncSession, older_than_days: int) -> int:
    cutoff = utcnow() - timedelta(days=older_than_days)
    res = await db.execute(delete(Event).where(Event.received_at < cutoff))
    await db.commit()
    return int(res.rowcount or 0)  # type: ignore[attr-defined]

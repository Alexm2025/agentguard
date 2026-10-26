"""Tamper-evident audit log.

Each organisation has its own chain. ``hash = sha256(prev_hash + canonical_json(entry))`` where the
entry covers org, seq, timestamp, actor, action, target and details. Changing, deleting or
reordering any row breaks verification from that row on. The chain head can be exported and stored
externally (e.g. in a SIEM) to also detect truncation of the tail.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections import defaultdict
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.core.events import scrub
from agentguard.server.models import AuditLog, utcnow

GENESIS = "0" * 64
_locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)


def canonical(
    org_id: str, seq: int, ts: datetime, actor: str, action: str, target: str, details: dict[str, Any]
) -> bytes:
    return json.dumps(
        {
            "org_id": org_id,
            "seq": seq,
            "ts": ts.isoformat(),
            "actor": actor,
            "action": action,
            "target": target,
            "details": details,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode()


def chain_hash(prev: str, payload: bytes) -> str:
    return hashlib.sha256(prev.encode() + payload).hexdigest()


def _ts(value: datetime) -> datetime:
    # SQLite returns naive datetimes; normalise so hashing is stable across backends.
    from datetime import UTC

    return value if value.tzinfo else value.replace(tzinfo=UTC)


async def append(
    db: AsyncSession,
    org_id: str,
    actor: str,
    action: str,
    target: str = "",
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Append an entry and commit. Serialised per org; the (org_id, seq) unique constraint guards
    against concurrent writers in other processes (the losing transaction fails and is retried)."""
    # Normalise to plain JSON so the hash is identical after a database round-trip.
    details = json.loads(json.dumps(scrub(details or {}), default=str))
    async with _locks[org_id]:
        for _attempt in range(5):
            last = (
                await db.execute(
                    select(AuditLog).where(AuditLog.org_id == org_id).order_by(AuditLog.seq.desc()).limit(1)
                )
            ).scalar_one_or_none()
            seq = (last.seq + 1) if last else 1
            prev = last.hash if last else GENESIS
            ts = utcnow()
            row = AuditLog(
                org_id=org_id,
                seq=seq,
                ts=ts,
                actor=actor[:200],
                action=action[:100],
                target=target[:300],
                details=details,
                prev_hash=prev,
                hash=chain_hash(prev, canonical(org_id, seq, ts, actor[:200], action[:100], target[:300], details)),
            )
            db.add(row)
            try:
                await db.commit()
                return row
            except Exception:
                await db.rollback()
        raise RuntimeError("could not append audit entry")


async def verify(db: AsyncSession, org_id: str) -> dict[str, Any]:
    rows = (await db.execute(select(AuditLog).where(AuditLog.org_id == org_id).order_by(AuditLog.seq))).scalars().all()
    prev = GENESIS
    for i, r in enumerate(rows, start=1):
        if r.seq != i:
            return {
                "valid": False,
                "entries": len(rows),
                "broken_at": r.seq,
                "reason": "sequence gap or reorder",
            }
        if r.prev_hash != prev:
            return {"valid": False, "entries": len(rows), "broken_at": r.seq, "reason": "prev_hash mismatch"}
        expected = chain_hash(prev, canonical(r.org_id, r.seq, _ts(r.ts), r.actor, r.action, r.target, r.details))
        if expected != r.hash:
            return {"valid": False, "entries": len(rows), "broken_at": r.seq, "reason": "entry modified"}
        prev = r.hash
    return {"valid": True, "entries": len(rows), "head": prev}


def to_dict(r: AuditLog) -> dict[str, Any]:
    return {
        "seq": r.seq,
        "ts": _ts(r.ts).isoformat(),
        "actor": r.actor,
        "action": r.action,
        "target": r.target,
        "details": r.details,
        "prev_hash": r.prev_hash,
        "hash": r.hash,
    }

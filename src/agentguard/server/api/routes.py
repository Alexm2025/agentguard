"""REST API (``/api/v1``)."""

from __future__ import annotations

import hmac
import json
import re
from datetime import timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.core.policy.loader import validate_policy_data
from agentguard.server import audit, services
from agentguard.server.auth import (
    PERMISSIONS,
    ROLES,
    SESSION_COOKIE,
    VALID_SCOPES,
    Principal,
    _client_ip,
    create_session,
    current_principal,
    get_db,
    require,
)
from agentguard.server.models import (
    ApiKey,
    Approval,
    AuditLog,
    Event,
    FalsePositiveReport,
    Membership,
    Organization,
    Policy,
    PolicyVersion,
    Project,
    User,
    WebSession,
    utcnow,
)
from agentguard.server.security import generate_api_key, hash_password, sha256, unsign, verify_password

router = APIRouter(prefix="/api/v1")
SLUG = re.compile(r"^[a-z0-9][a-z0-9\-]{0,62}$")
# Deliberately permissive: internal domains (.internal, .corp, .test) must work.
EMAIL_PATTERN = r"^[^@\s]{1,64}@[^@\s]{1,255}$"


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid", str_max_length=20_000)


def settings_of(request: Request) -> Any:
    return request.app.state.settings


# ---------------------------------------------------------------- auth


class LoginIn(_In):
    email: str = Field(pattern=EMAIL_PATTERN, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


@router.post("/auth/login")
async def login(
    body: LoginIn, request: Request, response: Response, db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    settings = settings_of(request)
    limiter = request.app.state.rate_limiter
    ip = _client_ip(request, settings)
    if not limiter.hit(f"login:{ip}:{body.email.lower()}", settings.login_rate_limit, 300):
        raise HTTPException(status_code=429, detail="too many login attempts; try again later")
    user = (await db.execute(select(User).where(User.email == body.email.lower()))).scalar_one_or_none()
    if not verify_password(body.password, user.password_hash if user else None) or user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="invalid email or password")
    mem = (
        (await db.execute(select(Membership).where(Membership.user_id == user.id).order_by(Membership.created_at)))
        .scalars()
        .first()
    )
    if mem is None:
        raise HTTPException(status_code=403, detail="user is not a member of any organization")
    token, ws = await create_session(db, user, mem.org_id, request, settings)
    set_session_cookie(response, token, settings)
    await audit.append(db, mem.org_id, f"user:{user.email}", "auth.login", user.id, {"ip": ip})
    return {
        "user": {"id": user.id, "email": user.email, "role": mem.role},
        "org_id": mem.org_id,
        "csrf_token": ws.csrf_token,
    }


def set_session_cookie(response: Response, token: str, settings: Any) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="strict",
        max_age=int(settings.session_ttl_hours * 3600),
        path="/",
    )


@router.post("/auth/logout")
async def logout(
    request: Request,
    response: Response,
    p: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        ws = await db.get(WebSession, sha256(token))
        if ws:
            await db.delete(ws)
            await db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"status": "ok"}


@router.get("/auth/me")
async def me(p: Principal = Depends(current_principal)) -> dict[str, Any]:
    perms = sorted(k for k in PERMISSIONS if p.can(k))
    return {
        "kind": p.kind,
        "id": p.id,
        "display": p.display,
        "org_id": p.org_id,
        "role": p.role,
        "scopes": sorted(p.scopes),
        "permissions": perms,
        "csrf_token": p.csrf_token,
    }


class IntrospectIn(_In):
    key: str = Field(min_length=10, max_length=200)


@router.post("/auth/introspect")
async def introspect(body: IntrospectIn, request: Request, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """Used by gateways (service token) to validate an AgentGuard API key."""
    settings = settings_of(request)
    auth = request.headers.get("authorization", "")
    if not settings.service_token or not hmac.compare_digest(auth, f"Bearer {settings.service_token}"):
        raise HTTPException(status_code=401, detail="invalid service token")
    from agentguard.server.auth import principal_from_key

    p = await principal_from_key(db, body.key)
    if p is None:
        return {"active": False}
    return {
        "active": True,
        "org_id": p.org_id,
        "project_id": p.project_id,
        "key_id": p.id,
        "scopes": sorted(p.scopes),
    }


# ---------------------------------------------------------------- org, members, projects


@router.get("/org")
async def get_org(p: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    org = await db.get(Organization, p.org_id)
    if org is None:  # pragma: no cover - an authenticated principal implies the org exists
        raise HTTPException(status_code=404, detail="organization not found")
    settings = dict(org.settings or {})
    if "approval_webhook" in settings:
        settings["approval_webhook"] = {"url": settings["approval_webhook"].get("url"), "secret": "********"}  # nosec B105 - display mask, not a credential
    return {"id": org.id, "name": org.name, "slug": org.slug, "settings": settings}


class OrgSettingsIn(_In):
    approval_webhook_url: str | None = Field(default=None, max_length=2000, pattern=r"^https?://")
    approval_webhook_secret: str | None = Field(default=None, min_length=16, max_length=200)


@router.patch("/org/settings")
async def update_org_settings(
    body: OrgSettingsIn, p: Principal = Depends(require("settings:write")), db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
    org = await db.get(Organization, p.org_id)
    if org is None:  # pragma: no cover - an authenticated principal implies the org exists
        raise HTTPException(status_code=404, detail="organization not found")
    s = dict(org.settings or {})
    if body.approval_webhook_url is None:
        s.pop("approval_webhook", None)
    else:
        if not body.approval_webhook_secret:
            raise HTTPException(status_code=422, detail="approval_webhook_secret is required with a webhook URL")
        s["approval_webhook"] = {"url": body.approval_webhook_url, "secret": body.approval_webhook_secret}
    org.settings = s
    await db.commit()
    await audit.append(
        db,
        p.org_id,
        p.actor,
        "org.settings_updated",
        org.id,
        {"approval_webhook_url": body.approval_webhook_url},
    )
    return {"status": "ok"}


class MemberIn(_In):
    email: str = Field(pattern=EMAIL_PATTERN, max_length=320)
    name: str = Field(default="", max_length=200)
    role: Literal["admin", "analyst", "viewer"]
    password: str | None = Field(default=None, min_length=12, max_length=1024)


@router.get("/members")
async def list_members(
    p: Principal = Depends(require("members:manage")), db: AsyncSession = Depends(get_db)
) -> list[dict[str, Any]]:
    rows = (
        await db.execute(
            select(Membership, User).join(User, User.id == Membership.user_id).where(Membership.org_id == p.org_id)
        )
    ).all()
    return [{"user_id": u.id, "email": u.email, "name": u.name, "role": m.role, "active": u.is_active} for m, u in rows]


@router.post("/members", status_code=201)
async def add_member(
    body: MemberIn, p: Principal = Depends(require("members:manage")), db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    email = body.email.lower()
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if user is None:
        user = User(email=email, name=body.name, password_hash=hash_password(body.password) if body.password else None)
        db.add(user)
        await db.flush()
    exists = (
        await db.execute(select(Membership).where(Membership.org_id == p.org_id, Membership.user_id == user.id))
    ).scalar_one_or_none()
    if exists:
        raise HTTPException(status_code=409, detail="already a member")
    db.add(Membership(org_id=p.org_id, user_id=user.id, role=body.role))
    await db.commit()
    await audit.append(db, p.org_id, p.actor, "member.added", user.id, {"email": email, "role": body.role})
    return {"user_id": user.id, "email": email, "role": body.role}


class RoleIn(_In):
    role: Literal["admin", "analyst", "viewer"]


@router.patch("/members/{user_id}")
async def change_role(
    user_id: str,
    body: RoleIn,
    p: Principal = Depends(require("members:manage")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    mem = (
        await db.execute(select(Membership).where(Membership.org_id == p.org_id, Membership.user_id == user_id))
    ).scalar_one_or_none()
    if mem is None:
        raise HTTPException(status_code=404, detail="not found")
    if mem.role == "admin" and body.role != "admin" and await _admin_count(db, p.org_id) <= 1:
        raise HTTPException(status_code=409, detail="cannot demote the last admin")
    mem.role = body.role
    await db.commit()
    await audit.append(db, p.org_id, p.actor, "member.role_changed", user_id, {"role": body.role})
    return {"status": "ok"}


async def _admin_count(db: AsyncSession, org_id: str) -> int:
    return int(
        (
            await db.execute(
                select(func.count())
                .select_from(Membership)
                .where(Membership.org_id == org_id, Membership.role == "admin")
            )
        ).scalar()
        or 0
    )


@router.delete("/members/{user_id}", status_code=204)
async def remove_member(
    user_id: str, p: Principal = Depends(require("members:manage")), db: AsyncSession = Depends(get_db)
) -> Response:
    mem = (
        await db.execute(select(Membership).where(Membership.org_id == p.org_id, Membership.user_id == user_id))
    ).scalar_one_or_none()
    if mem is None:
        raise HTTPException(status_code=404, detail="not found")
    if mem.role == "admin" and await _admin_count(db, p.org_id) <= 1:
        raise HTTPException(status_code=409, detail="cannot remove the last admin")
    await db.delete(mem)
    await db.commit()
    await audit.append(db, p.org_id, p.actor, "member.removed", user_id, {})
    return Response(status_code=204)


class ProjectIn(_In):
    name: str = Field(min_length=1, max_length=200)
    slug: str = Field(pattern=SLUG.pattern)


@router.get("/projects")
async def list_projects(
    p: Principal = Depends(require("projects:read")), db: AsyncSession = Depends(get_db)
) -> list[dict[str, Any]]:
    rows = (
        (await db.execute(select(Project).where(Project.org_id == p.org_id).order_by(Project.created_at)))
        .scalars()
        .all()
    )
    return [{"id": r.id, "name": r.name, "slug": r.slug} for r in rows]


@router.post("/projects", status_code=201)
async def create_project(
    body: ProjectIn, p: Principal = Depends(require("projects:write")), db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    if (
        await db.execute(select(Project).where(Project.org_id == p.org_id, Project.slug == body.slug))
    ).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="slug already exists")
    prj = Project(org_id=p.org_id, name=body.name, slug=body.slug)
    db.add(prj)
    await db.commit()
    await audit.append(db, p.org_id, p.actor, "project.created", prj.id, {"slug": body.slug})
    return {"id": prj.id, "name": prj.name, "slug": prj.slug}


async def _project(db: AsyncSession, org_id: str, project_id: str | None) -> Project | None:
    if project_id is None:
        return None
    prj = await db.get(Project, project_id)
    if prj is None or prj.org_id != org_id:
        raise HTTPException(status_code=404, detail="project not found")
    return prj


# ---------------------------------------------------------------- API keys


class KeyIn(_In):
    name: str = Field(min_length=1, max_length=200)
    scopes: list[str] = Field(min_length=1, max_length=5)
    project_id: str | None = Field(default=None, max_length=40)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


@router.get("/api-keys")
async def list_keys(
    p: Principal = Depends(require("keys:manage")), db: AsyncSession = Depends(get_db)
) -> list[dict[str, Any]]:
    rows = (
        (await db.execute(select(ApiKey).where(ApiKey.org_id == p.org_id).order_by(ApiKey.created_at.desc())))
        .scalars()
        .all()
    )
    return [key_dict(r) for r in rows]


def key_dict(r: ApiKey) -> dict[str, Any]:
    return {
        "id": r.id,
        "name": r.name,
        "prefix": r.prefix,
        "scopes": r.scopes,
        "project_id": r.project_id,
        "created_at": r.created_at.isoformat(),
        "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
        "expires_at": r.expires_at.isoformat() if r.expires_at else None,
        "revoked": r.revoked_at is not None,
    }


@router.post("/api-keys", status_code=201)
async def create_key(
    body: KeyIn, p: Principal = Depends(require("keys:manage")), db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    bad = set(body.scopes) - VALID_SCOPES
    if bad:
        raise HTTPException(status_code=422, detail=f"unknown scopes: {sorted(bad)}")
    if p.kind == "api_key" and not set(body.scopes) <= p.scopes | (
        {"ingest", "read", "approve", "gateway"} if "admin" in p.scopes else set()
    ):
        raise HTTPException(status_code=403, detail="cannot mint a key with more privileges than your own")
    await _project(db, p.org_id, body.project_id)
    key, prefix, digest = generate_api_key()
    row = ApiKey(
        org_id=p.org_id,
        project_id=body.project_id,
        name=body.name,
        prefix=prefix,
        key_hash=digest,
        scopes=sorted(set(body.scopes)),
        created_by=p.id,
        expires_at=utcnow() + timedelta(days=body.expires_in_days) if body.expires_in_days else None,
    )
    db.add(row)
    await db.commit()
    await audit.append(
        db,
        p.org_id,
        p.actor,
        "api_key.created",
        row.id,
        {"name": body.name, "scopes": row.scopes, "prefix": prefix},
    )
    return {**key_dict(row), "key": key}


@router.delete("/api-keys/{key_id}", status_code=204)
async def revoke_key(
    key_id: str, p: Principal = Depends(require("keys:manage")), db: AsyncSession = Depends(get_db)
) -> Response:
    row = await db.get(ApiKey, key_id)
    if row is None or row.org_id != p.org_id:
        raise HTTPException(status_code=404, detail="not found")
    row.revoked_at = utcnow()
    await db.commit()
    await audit.append(db, p.org_id, p.actor, "api_key.revoked", key_id, {"prefix": row.prefix})
    return Response(status_code=204)


# ---------------------------------------------------------------- policies


class PolicyIn(_In):
    name: str = Field(pattern=r"^[A-Za-z0-9_.\-]{1,100}$")
    yaml: str = Field(min_length=0, max_length=1_000_000)
    project_id: str | None = Field(default=None, max_length=40)
    comment: str = Field(default="", max_length=500)


class PolicyVersionIn(_In):
    yaml: str = Field(max_length=1_000_000)
    comment: str = Field(default="", max_length=500)
    activate: bool = True


class ValidateIn(_In):
    yaml: str = Field(max_length=1_000_000)


@router.post("/policies/validate")
async def validate(body: ValidateIn, p: Principal = Depends(require("policies:read"))) -> dict[str, Any]:
    import yaml as _yaml

    try:
        data = _yaml.safe_load(body.yaml) or {}
    except _yaml.YAMLError as exc:
        return {"valid": False, "errors": [f"invalid YAML: {exc}"]}
    errors = validate_policy_data(data)
    return {"valid": not errors, "errors": errors}


@router.get("/policies")
async def list_policies(
    p: Principal = Depends(require("policies:read")), db: AsyncSession = Depends(get_db)
) -> list[dict[str, Any]]:
    rows = (
        (await db.execute(select(Policy).where(Policy.org_id == p.org_id).order_by(Policy.created_at))).scalars().all()
    )
    return [
        {"id": r.id, "name": r.name, "project_id": r.project_id, "active_revision": r.active_revision} for r in rows
    ]


@router.post("/policies", status_code=201)
async def create_policy(
    body: PolicyIn, p: Principal = Depends(require("policies:write")), db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    await _project(db, p.org_id, body.project_id)
    if (
        await db.execute(select(Policy).where(Policy.org_id == p.org_id, Policy.name == body.name))
    ).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="policy name exists")
    pol = Policy(org_id=p.org_id, project_id=body.project_id, name=body.name)
    db.add(pol)
    await db.flush()
    try:
        pv = await services.create_policy_version(db, pol, body.yaml, p.actor, body.comment)
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"id": pol.id, "name": pol.name, "active_revision": pv.revision, "digest": pv.digest}


async def _policy(db: AsyncSession, org_id: str, policy_id: str) -> Policy:
    pol = await db.get(Policy, policy_id)
    if pol is None or pol.org_id != org_id:
        raise HTTPException(status_code=404, detail="not found")
    return pol


@router.get("/policies/active")
async def get_active_policy(
    project_id: str | None = Query(default=None, max_length=40),
    p: Principal = Depends(require("policies:fetch")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    found = await services.active_policy(db, p.org_id, p.project_id or project_id)
    if found is None:
        raise HTTPException(status_code=404, detail="no active policy")
    pol, pv = found
    return {
        "policy_id": pol.id,
        "name": pol.name,
        "revision": pv.revision,
        "digest": pv.digest,
        "yaml": pv.yaml,
    }


@router.get("/policies/{policy_id}")
async def get_policy(
    policy_id: str, p: Principal = Depends(require("policies:read")), db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    pol = await _policy(db, p.org_id, policy_id)
    versions = (
        (
            await db.execute(
                select(PolicyVersion).where(PolicyVersion.policy_id == pol.id).order_by(PolicyVersion.revision.desc())
            )
        )
        .scalars()
        .all()
    )
    return {
        "id": pol.id,
        "name": pol.name,
        "project_id": pol.project_id,
        "active_revision": pol.active_revision,
        "versions": [
            {
                "revision": v.revision,
                "digest": v.digest,
                "comment": v.comment,
                "created_by": v.created_by,
                "created_at": v.created_at.isoformat(),
                "yaml": v.yaml,
            }
            for v in versions
        ],
    }


@router.post("/policies/{policy_id}/versions", status_code=201)
async def add_version(
    policy_id: str,
    body: PolicyVersionIn,
    p: Principal = Depends(require("policies:write")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    pol = await _policy(db, p.org_id, policy_id)
    try:
        pv = await services.create_policy_version(db, pol, body.yaml, p.actor, body.comment, body.activate)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"revision": pv.revision, "digest": pv.digest, "active_revision": pol.active_revision}


@router.post("/policies/{policy_id}/activate/{revision}")
async def activate(
    policy_id: str,
    revision: int,
    p: Principal = Depends(require("policies:write")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    pol = await _policy(db, p.org_id, policy_id)
    pv = (
        await db.execute(
            select(PolicyVersion).where(PolicyVersion.policy_id == pol.id, PolicyVersion.revision == revision)
        )
    ).scalar_one_or_none()
    if pv is None:
        raise HTTPException(status_code=404, detail="revision not found")
    pol.active_revision = revision
    await db.commit()
    await audit.append(db, p.org_id, p.actor, "policy.activated", pol.id, {"revision": revision})
    return {"active_revision": revision}


# ---------------------------------------------------------------- events


@router.post("/events", status_code=202)
async def post_events(
    request: Request, p: Principal = Depends(require("events:write")), db: AsyncSession = Depends(get_db)
) -> dict[str, int]:
    raw = await request.body()
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="batch too large")
    try:
        body = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="invalid JSON") from exc
    events = body.get("events") if isinstance(body, dict) else body
    if not isinstance(events, list):
        raise HTTPException(status_code=422, detail="expected {'events': [...]}")
    if len(events) > settings_of(request).max_events_per_batch:
        raise HTTPException(status_code=413, detail="too many events in batch")
    n = await services.ingest_events(db, p.org_id, p.project_id, events, request.app.state.event_forwarders)
    return {"accepted": n}


@router.get("/events")
async def list_events(
    p: Principal = Depends(require("events:read")),
    db: AsyncSession = Depends(get_db),
    action: str | None = Query(default=None, pattern=r"^(ALLOW|BLOCK|REDACT|REQUIRE_APPROVAL)$"),
    type: str | None = Query(default=None, max_length=40),
    tool: str | None = Query(default=None, max_length=200),
    project_id: str | None = Query(default=None, max_length=40),
    session_id: str | None = Query(default=None, max_length=128),
    before: str | None = Query(default=None, max_length=64, description="cursor: event id"),
    limit: int = Query(default=50, ge=1, le=500),
) -> dict[str, Any]:
    q = select(Event).where(Event.org_id == p.org_id)
    if action:
        q = q.where(Event.action == action)
    if type:
        q = q.where(Event.type == type)
    if tool:
        q = q.where(Event.tool == tool)
    if project_id:
        q = q.where(Event.project_id == project_id)
    if session_id:
        q = q.where(Event.session_id == session_id)
    if before:
        cur = await db.get(Event, before)
        if cur is not None and cur.org_id == p.org_id:
            q = q.where(Event.timestamp < cur.timestamp)
    rows = (await db.execute(q.order_by(Event.timestamp.desc()).limit(limit))).scalars().all()
    return {"events": [r.data for r in rows], "next": rows[-1].id if len(rows) == limit else None}


@router.get("/events/{event_id}")
async def get_event(
    event_id: str, p: Principal = Depends(require("events:read")), db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    ev = await db.get(Event, event_id)
    if ev is None or ev.org_id != p.org_id:
        raise HTTPException(status_code=404, detail="not found")
    related = []
    if ev.session_id:
        rows = (
            (
                await db.execute(
                    select(Event)
                    .where(
                        Event.org_id == p.org_id,
                        Event.session_id == ev.session_id,
                        Event.timestamp <= ev.timestamp,
                    )
                    .order_by(Event.timestamp)
                    .limit(200)
                )
            )
            .scalars()
            .all()
        )
        related = [r.data for r in rows if r.id != ev.id]
    return {"event": ev.data, "session_events": related}


class FpIn(_In):
    note: str = Field(default="", max_length=2000)


@router.post("/events/{event_id}/false-positive", status_code=201)
async def report_fp(
    event_id: str, body: FpIn, p: Principal = Depends(require("fp:write")), db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
    ev = await db.get(Event, event_id)
    if ev is None or ev.org_id != p.org_id:
        raise HTTPException(status_code=404, detail="not found")
    fp = FalsePositiveReport(org_id=p.org_id, event_id=event_id, reporter=p.actor, note=body.note)
    db.add(fp)
    await db.commit()
    await audit.append(db, p.org_id, p.actor, "event.false_positive_reported", event_id, {"note": body.note[:200]})
    return {"id": fp.id}


@router.get("/false-positives")
async def list_fps(
    p: Principal = Depends(require("events:read")), db: AsyncSession = Depends(get_db)
) -> list[dict[str, Any]]:
    rows = (
        (
            await db.execute(
                select(FalsePositiveReport)
                .where(FalsePositiveReport.org_id == p.org_id)
                .order_by(FalsePositiveReport.created_at.desc())
                .limit(500)
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": r.id,
            "event_id": r.event_id,
            "reporter": r.reporter,
            "note": r.note,
            "status": r.status,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


# ---------------------------------------------------------------- approvals


class ApprovalIn(_In):
    model_config = ConfigDict(extra="forbid")
    event: dict[str, Any]
    timeout_seconds: float = Field(default=300, gt=0, le=86_400)


@router.post("/approvals", status_code=201)
async def create_approval(
    body: ApprovalIn,
    request: Request,
    p: Principal = Depends(require("approvals:create")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    org = await db.get(Organization, p.org_id)
    if org is None:  # pragma: no cover - an authenticated principal implies the org exists
        raise HTTPException(status_code=404, detail="organization not found")
    apr = await services.create_approval(
        db,
        org,
        p.project_id,
        body.event,
        body.timeout_seconds,
        settings_of(request),
        request.app.state.approval_notifiers,
    )
    return services.approval_dict(apr)


@router.get("/approvals")
async def list_approvals(
    p: Principal = Depends(require("approvals:read")),
    db: AsyncSession = Depends(get_db),
    status: str | None = Query(default=None, pattern=r"^(pending|approved|denied|expired)$"),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    q = select(Approval).where(Approval.org_id == p.org_id)
    if status in ("approved", "denied"):
        q = q.where(Approval.status == status)
    elif status in ("pending", "expired"):
        q = q.where(Approval.status == "pending")
    rows = (await db.execute(q.order_by(Approval.created_at.desc()).limit(limit))).scalars().all()
    out = [services.approval_dict(r) for r in rows]
    return [a for a in out if status is None or a["status"] == status]


async def _approval(db: AsyncSession, org_id: str, approval_id: str) -> Approval:
    apr = await db.get(Approval, approval_id)
    if apr is None or apr.org_id != org_id:
        raise HTTPException(status_code=404, detail="not found")
    return apr


@router.get("/approvals/{approval_id}")
async def get_approval(
    approval_id: str, p: Principal = Depends(require("approvals:status")), db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    return services.approval_dict(await _approval(db, p.org_id, approval_id))


class ResolveIn(_In):
    decision: Literal["approve", "deny"]
    note: str = Field(default="", max_length=1000)


@router.post("/approvals/{approval_id}/resolve")
async def resolve(
    approval_id: str,
    body: ResolveIn,
    p: Principal = Depends(require("approvals:resolve")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    apr = await _approval(db, p.org_id, approval_id)
    try:
        await services.resolve_approval(
            db, apr, body.decision, p.actor, body.note, "dashboard" if p.kind == "user" else "api"
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return services.approval_dict(apr)


class WebhookResolveIn(_In):
    token: str = Field(max_length=2000)
    actor: str = Field(default="webhook", max_length=200)
    note: str = Field(default="", max_length=1000)


@router.post("/approvals/{approval_id}/webhook-resolve")
async def webhook_resolve(
    approval_id: str, body: WebhookResolveIn, request: Request, db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    claims = unsign(body.token, settings_of(request).secret_key)
    if claims is None or claims.get("apr") != approval_id:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    apr = await _approval(db, str(claims["org"]), approval_id)
    try:
        await services.resolve_approval(db, apr, str(claims["d"]), f"webhook:{body.actor}", body.note, "webhook")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return services.approval_dict(apr)


# ---------------------------------------------------------------- metrics & audit


@router.get("/metrics/summary")
async def metrics(
    p: Principal = Depends(require("metrics:read")),
    db: AsyncSession = Depends(get_db),
    hours: int = Query(default=24, ge=1, le=24 * 90),
) -> dict[str, Any]:
    return await services.metrics_summary(db, p.org_id, hours)


@router.get("/audit")
async def get_audit(
    p: Principal = Depends(require("audit:read")),
    db: AsyncSession = Depends(get_db),
    after_seq: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=5000),
) -> list[dict[str, Any]]:
    rows = (
        (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.org_id == p.org_id, AuditLog.seq > after_seq)
                .order_by(AuditLog.seq)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return [audit.to_dict(r) for r in rows]


@router.get("/audit/export")
async def export_audit(
    p: Principal = Depends(require("audit:read")), db: AsyncSession = Depends(get_db)
) -> JSONResponse:
    rows = (
        (await db.execute(select(AuditLog).where(AuditLog.org_id == p.org_id).order_by(AuditLog.seq))).scalars().all()
    )
    verification = await audit.verify(db, p.org_id)
    body = {
        "org_id": p.org_id,
        "exported_at": utcnow().isoformat(),
        "verification": verification,
        "entries": [audit.to_dict(r) for r in rows],
    }
    return JSONResponse(
        body, headers={"content-disposition": f'attachment; filename="agentguard-audit-{p.org_id}.json"'}
    )


@router.get("/audit/verify")
async def verify_audit(
    p: Principal = Depends(require("audit:read")), db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    return await audit.verify(db, p.org_id)


@router.get("/roles")
async def roles(p: Principal = Depends(current_principal)) -> dict[str, Any]:
    return {
        "roles": list(ROLES),
        "scopes": sorted(VALID_SCOPES),
        "permissions": {k: {"min_role": v[0], "scope": v[1]} for k, v in PERMISSIONS.items()},
    }

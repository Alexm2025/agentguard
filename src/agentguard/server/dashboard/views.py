"""Server-rendered dashboard (Jinja2 + HTMX). All output is auto-escaped; no inline scripts."""

from __future__ import annotations

import hmac
import json
import secrets
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.staticfiles import StaticFiles

from agentguard.core.policy.loader import default_policy_text, validate_policy_data
from agentguard.server import audit, services
from agentguard.server.api.routes import set_session_cookie
from agentguard.server.auth import (
    SESSION_COOKIE,
    Principal,
    _client_ip,
    create_session,
    get_db,
    resolve_principal,
)
from agentguard.server.models import (
    ApiKey,
    Approval,
    Event,
    FalsePositiveReport,
    Membership,
    Policy,
    PolicyVersion,
    User,
    WebSession,
)
from agentguard.server.security import generate_api_key, sha256, verify_password

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(HERE / "templates"))
templates.env.filters["tojson_pretty"] = lambda v: json.dumps(v, indent=2, ensure_ascii=False, default=str)


def _ago(value: Any) -> str:
    """Human relative time ("3m ago") for datetimes or ISO strings."""
    from datetime import UTC, datetime

    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return str(value)
    if not isinstance(value, datetime):
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    secs = int((datetime.now(UTC) - value).total_seconds())
    if secs < 0:
        secs = -secs
        for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
            if secs >= size:
                return f"in {secs // size}{unit}"
        return "in <1m"
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= size:
            return f"{secs // size}{unit} ago"
    return "just now"


def _attack_path(d: dict[str, Any]) -> list[dict[str, Any]]:
    """Group derived taint matches by (source, argument) for the attack-path diagram."""
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for m in d.get("taint_matches") or []:
        if m.get("also_in_trusted"):
            continue
        key = (str(m.get("source")), str(m.get("arg_path")))
        cur = seen.get(key)
        if cur is None or float(m.get("score") or 0) > float(cur.get("score") or 0):
            seen[key] = m
    return list(seen.values())[:6]


templates.env.filters["ago"] = _ago
templates.env.filters["attack_path"] = _attack_path
router = APIRouter(include_in_schema=False)
LOGIN_CSRF = "ag_login_csrf"


def static_app() -> StaticFiles:
    return StaticFiles(directory=str(HERE / "static"))


class LoginRequired(Exception):
    pass


async def ui_principal(request: Request, db: AsyncSession = Depends(get_db)) -> Principal:
    if request.cookies.get(SESSION_COOKIE) is None:
        raise HTTPException(status_code=303, headers={"location": "/login"})
    p = await resolve_principal(request, db)
    if p is None or p.kind != "user":
        raise HTTPException(status_code=303, headers={"location": "/login"})
    return p


def need(p: Principal, permission: str) -> None:
    if not p.can(permission):
        raise HTTPException(status_code=403, detail=f"your role cannot {permission}")


def render(request: Request, name: str, p: Principal | None, **ctx: Any) -> HTMLResponse:
    features = request.app.state.features
    return templates.TemplateResponse(request, name, {"p": p, "features": features, **ctx})


# ---------------------------------------------------------------- login


@router.get("/login")
async def login_form(request: Request) -> Response:
    token = secrets.token_urlsafe(24)
    resp = render(request, "login.html", None, csrf=token, error=None, sso=request.app.state.features.get("oidc"))
    resp.set_cookie(
        LOGIN_CSRF,
        token,
        httponly=True,
        samesite="strict",
        secure=request.app.state.settings.secure_cookies,
        max_age=900,
    )
    return resp


@router.post("/login")
async def login_submit(
    request: Request,
    email: str = Form(max_length=320),
    password: str = Form(max_length=1024),
    csrf_token: str = Form(max_length=100),
    db: AsyncSession = Depends(get_db),
) -> Response:
    settings = request.app.state.settings
    cookie = request.cookies.get(LOGIN_CSRF, "")
    if not cookie or not hmac.compare_digest(cookie, csrf_token):
        raise HTTPException(status_code=403, detail="invalid login form token; reload the page")
    ip = _client_ip(request, settings)
    if not request.app.state.rate_limiter.hit(f"login:{ip}:{email.lower()}", settings.login_rate_limit, 300):
        return render(
            request,
            "login.html",
            None,
            csrf=csrf_token,
            error="Too many attempts. Try again in a few minutes.",
            sso=None,
        )
    user = (await db.execute(select(User).where(User.email == email.lower()))).scalar_one_or_none()
    if not verify_password(password, user.password_hash if user else None) or user is None or not user.is_active:
        return render(
            request,
            "login.html",
            None,
            csrf=csrf_token,
            error="Invalid email or password.",
            sso=request.app.state.features.get("oidc"),
        )
    mem = (
        (await db.execute(select(Membership).where(Membership.user_id == user.id).order_by(Membership.created_at)))
        .scalars()
        .first()
    )
    if mem is None:
        return render(request, "login.html", None, csrf=csrf_token, error="Your account has no organization.", sso=None)
    token, _ = await create_session(db, user, mem.org_id, request, settings)
    await audit.append(db, mem.org_id, f"user:{user.email}", "auth.login", user.id, {"ip": ip, "via": "dashboard"})
    resp = RedirectResponse("/events", status_code=303)
    set_session_cookie(resp, token, settings)
    resp.delete_cookie(LOGIN_CSRF)
    return resp


@router.post("/logout")
async def logout(
    request: Request, p: Principal = Depends(ui_principal), db: AsyncSession = Depends(get_db)
) -> Response:
    token = request.cookies.get(SESSION_COOKIE)
    if token and (ws := await db.get(WebSession, sha256(token))):
        await db.delete(ws)
        await db.commit()
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@router.get("/")
async def index() -> Response:
    return RedirectResponse("/events", status_code=303)


# ---------------------------------------------------------------- events


async def _events(db: AsyncSession, org_id: str, action: str | None, limit: int = 100) -> list[Event]:
    q = select(Event).where(Event.org_id == org_id)
    if action in ("ALLOW", "BLOCK", "REDACT", "REQUIRE_APPROVAL"):
        q = q.where(Event.action == action)
    return list((await db.execute(q.order_by(Event.timestamp.desc()).limit(limit))).scalars().all())


@router.get("/events")
async def events_page(
    request: Request,
    action: str | None = None,
    p: Principal = Depends(ui_principal),
    db: AsyncSession = Depends(get_db),
) -> Response:
    need(p, "events:read")
    from sqlalchemy import func

    pending = int(
        (
            await db.execute(
                select(func.count())
                .select_from(Approval)
                .where(Approval.org_id == p.org_id, Approval.status == "pending")
            )
        ).scalar()
        or 0
    )
    return render(
        request,
        "events.html",
        p,
        events=await _events(db, p.org_id, action),
        action=action or "",
        m=await services.metrics_summary(db, p.org_id, 24),
        pending=pending,
    )


@router.get("/events/feed")
async def events_feed(
    request: Request,
    action: str | None = None,
    p: Principal = Depends(ui_principal),
    db: AsyncSession = Depends(get_db),
) -> Response:
    need(p, "events:read")
    return render(request, "_event_rows.html", p, events=await _events(db, p.org_id, action))


@router.get("/events/{event_id}")
async def event_detail(
    event_id: str, request: Request, p: Principal = Depends(ui_principal), db: AsyncSession = Depends(get_db)
) -> Response:
    need(p, "events:read")
    ev = await db.get(Event, event_id)
    if ev is None or ev.org_id != p.org_id:
        raise HTTPException(status_code=404, detail="event not found")
    timeline: list[Event] = []
    if ev.session_id:
        timeline = list(
            (
                await db.execute(
                    select(Event)
                    .where(Event.org_id == p.org_id, Event.session_id == ev.session_id)
                    .order_by(Event.timestamp)
                    .limit(200)
                )
            )
            .scalars()
            .all()
        )
    fps = (
        (
            await db.execute(
                select(FalsePositiveReport).where(
                    FalsePositiveReport.org_id == p.org_id, FalsePositiveReport.event_id == ev.id
                )
            )
        )
        .scalars()
        .all()
    )
    return render(request, "event_detail.html", p, ev=ev, d=ev.data, timeline=timeline, fps=fps)


@router.post("/events/{event_id}/false-positive")
async def event_fp(
    event_id: str,
    request: Request,
    note: str = Form(default="", max_length=2000),
    p: Principal = Depends(ui_principal),
    db: AsyncSession = Depends(get_db),
) -> Response:
    need(p, "fp:write")
    ev = await db.get(Event, event_id)
    if ev is None or ev.org_id != p.org_id:
        raise HTTPException(status_code=404, detail="event not found")
    db.add(FalsePositiveReport(org_id=p.org_id, event_id=event_id, reporter=p.actor, note=note))
    await db.commit()
    await audit.append(db, p.org_id, p.actor, "event.false_positive_reported", event_id, {"note": note[:200]})
    return RedirectResponse(f"/events/{event_id}", status_code=303)


# ---------------------------------------------------------------- approvals


@router.get("/approvals")
async def approvals_page(
    request: Request, p: Principal = Depends(ui_principal), db: AsyncSession = Depends(get_db)
) -> Response:
    need(p, "approvals:read")
    rows = (
        (
            await db.execute(
                select(Approval).where(Approval.org_id == p.org_id).order_by(Approval.created_at.desc()).limit(200)
            )
        )
        .scalars()
        .all()
    )
    items = [services.approval_dict(a) for a in rows]
    return render(
        request,
        "approvals.html",
        p,
        pending=[a for a in items if a["status"] == "pending"],
        history=[a for a in items if a["status"] != "pending"][:100],
    )


@router.get("/approvals/{approval_id}")
async def approval_detail(
    approval_id: str,
    request: Request,
    p: Principal = Depends(ui_principal),
    db: AsyncSession = Depends(get_db),
) -> Response:
    need(p, "approvals:read")
    apr = await db.get(Approval, approval_id)
    if apr is None or apr.org_id != p.org_id:
        raise HTTPException(status_code=404, detail="approval not found")
    return render(request, "approval_detail.html", p, a=services.approval_dict(apr), d=apr.data)


@router.post("/approvals/{approval_id}/resolve")
async def approval_resolve(
    approval_id: str,
    request: Request,
    decision: str = Form(pattern="^(approve|deny)$"),
    note: str = Form(default="", max_length=1000),
    p: Principal = Depends(ui_principal),
    db: AsyncSession = Depends(get_db),
) -> Response:
    need(p, "approvals:resolve")
    apr = await db.get(Approval, approval_id)
    if apr is None or apr.org_id != p.org_id:
        raise HTTPException(status_code=404, detail="approval not found")
    error = None
    try:
        await services.resolve_approval(db, apr, decision, p.actor, note, "dashboard")
    except ValueError as exc:
        error = str(exc)
    if request.headers.get("hx-request"):
        return render(request, "_approval_row.html", p, a=services.approval_dict(apr), error=error)
    return RedirectResponse(f"/approvals/{approval_id}", status_code=303)


# ---------------------------------------------------------------- policies


@router.get("/policies")
async def policies_page(
    request: Request, p: Principal = Depends(ui_principal), db: AsyncSession = Depends(get_db)
) -> Response:
    need(p, "policies:read")
    rows = (
        (await db.execute(select(Policy).where(Policy.org_id == p.org_id).order_by(Policy.created_at))).scalars().all()
    )
    return render(request, "policies.html", p, policies=rows)


@router.get("/policies/new")
async def policy_new(request: Request, p: Principal = Depends(ui_principal)) -> Response:
    need(p, "policies:write")
    return render(
        request,
        "policy_edit.html",
        p,
        policy=None,
        versions=[],
        text=default_policy_text(),
        errors=[],
        saved=None,
    )


@router.post("/policies/new")
async def policy_create(
    request: Request,
    name: str = Form(pattern=r"^[A-Za-z0-9_.\-]{1,100}$"),
    yaml_text: str = Form(max_length=1_000_000),
    comment: str = Form(default="", max_length=500),
    p: Principal = Depends(ui_principal),
    db: AsyncSession = Depends(get_db),
) -> Response:
    need(p, "policies:write")
    if (await db.execute(select(Policy).where(Policy.org_id == p.org_id, Policy.name == name))).scalar_one_or_none():
        return render(
            request,
            "policy_edit.html",
            p,
            policy=None,
            versions=[],
            text=yaml_text,
            errors=["a policy with this name exists"],
            saved=None,
        )
    pol = Policy(org_id=p.org_id, name=name)
    db.add(pol)
    await db.flush()
    try:
        await services.create_policy_version(db, pol, yaml_text, p.actor, comment)
    except ValueError as exc:
        await db.rollback()
        return render(
            request,
            "policy_edit.html",
            p,
            policy=None,
            versions=[],
            text=yaml_text,
            errors=str(exc).split("; "),
            saved=None,
        )
    return RedirectResponse(f"/policies/{pol.id}", status_code=303)


@router.get("/policies/{policy_id}")
async def policy_edit(
    policy_id: str, request: Request, p: Principal = Depends(ui_principal), db: AsyncSession = Depends(get_db)
) -> Response:
    need(p, "policies:read")
    pol = await db.get(Policy, policy_id)
    if pol is None or pol.org_id != p.org_id:
        raise HTTPException(status_code=404, detail="policy not found")
    versions = (
        (
            await db.execute(
                select(PolicyVersion).where(PolicyVersion.policy_id == pol.id).order_by(PolicyVersion.revision.desc())
            )
        )
        .scalars()
        .all()
    )
    active = next((v for v in versions if v.revision == pol.active_revision), versions[0] if versions else None)
    return render(
        request,
        "policy_edit.html",
        p,
        policy=pol,
        versions=versions,
        text=active.yaml if active else "",
        errors=[],
        saved=None,
    )


@router.post("/policies/{policy_id}")
async def policy_save(
    policy_id: str,
    request: Request,
    yaml_text: str = Form(max_length=1_000_000),
    comment: str = Form(default="", max_length=500),
    p: Principal = Depends(ui_principal),
    db: AsyncSession = Depends(get_db),
) -> Response:
    need(p, "policies:write")
    pol = await db.get(Policy, policy_id)
    if pol is None or pol.org_id != p.org_id:
        raise HTTPException(status_code=404, detail="policy not found")
    errors: list[str] = []
    saved = None
    try:
        saved = (await services.create_policy_version(db, pol, yaml_text, p.actor, comment)).revision
    except ValueError as exc:
        errors = str(exc).split("; ")
    versions = (
        (
            await db.execute(
                select(PolicyVersion).where(PolicyVersion.policy_id == pol.id).order_by(PolicyVersion.revision.desc())
            )
        )
        .scalars()
        .all()
    )
    return render(
        request,
        "policy_edit.html",
        p,
        policy=pol,
        versions=versions,
        text=yaml_text,
        errors=errors,
        saved=saved,
    )


@router.post("/policies-validate")
async def policy_validate_fragment(
    request: Request, yaml_text: str = Form(max_length=1_000_000), p: Principal = Depends(ui_principal)
) -> Response:
    need(p, "policies:read")
    import yaml as _yaml

    try:
        errors = validate_policy_data(_yaml.safe_load(yaml_text) or {})
    except _yaml.YAMLError as exc:
        errors = [f"invalid YAML: {exc}"]
    return render(request, "_validation.html", p, errors=errors)


# ---------------------------------------------------------------- metrics


@router.get("/metrics")
async def metrics_page(
    request: Request,
    hours: int = 24,
    p: Principal = Depends(ui_principal),
    db: AsyncSession = Depends(get_db),
) -> Response:
    need(p, "metrics:read")
    hours = max(1, min(hours, 24 * 90))
    return render(request, "metrics.html", p, m=await services.metrics_summary(db, p.org_id, hours), hours=hours)


# ---------------------------------------------------------------- settings


@router.get("/settings")
async def settings_page(
    request: Request, p: Principal = Depends(ui_principal), db: AsyncSession = Depends(get_db)
) -> Response:
    keys = members = []
    verification = None
    if p.can("keys:manage"):
        keys = list(
            (await db.execute(select(ApiKey).where(ApiKey.org_id == p.org_id).order_by(ApiKey.created_at.desc())))
            .scalars()
            .all()
        )
    if p.can("members:manage"):
        members = list(
            (
                await db.execute(
                    select(Membership, User)
                    .join(User, User.id == Membership.user_id)
                    .where(Membership.org_id == p.org_id)
                )
            ).all()
        )
    if p.can("audit:read"):
        verification = await audit.verify(db, p.org_id)
    return render(request, "settings.html", p, keys=keys, members=members, verification=verification, new_key=None)


@router.post("/settings/keys")
async def settings_create_key(
    request: Request,
    name: str = Form(min_length=1, max_length=200),
    scopes: list[str] = Form(),
    p: Principal = Depends(ui_principal),
    db: AsyncSession = Depends(get_db),
) -> Response:
    need(p, "keys:manage")
    from agentguard.server.auth import VALID_SCOPES

    scopes = sorted(set(scopes) & VALID_SCOPES) or ["ingest"]
    key, prefix, digest = generate_api_key()
    row = ApiKey(org_id=p.org_id, name=name, prefix=prefix, key_hash=digest, scopes=scopes, created_by=p.id)
    db.add(row)
    await db.commit()
    await audit.append(
        db, p.org_id, p.actor, "api_key.created", row.id, {"name": name, "scopes": scopes, "prefix": prefix}
    )
    keys = list(
        (await db.execute(select(ApiKey).where(ApiKey.org_id == p.org_id).order_by(ApiKey.created_at.desc())))
        .scalars()
        .all()
    )
    members = list(
        (
            await db.execute(
                select(Membership, User).join(User, User.id == Membership.user_id).where(Membership.org_id == p.org_id)
            )
        ).all()
    )
    return render(
        request,
        "settings.html",
        p,
        keys=keys,
        members=members,
        verification=await audit.verify(db, p.org_id),
        new_key=key,
    )


@router.post("/settings/keys/{key_id}/revoke")
async def settings_revoke_key(
    key_id: str, p: Principal = Depends(ui_principal), db: AsyncSession = Depends(get_db)
) -> Response:
    need(p, "keys:manage")
    row = await db.get(ApiKey, key_id)
    if row is None or row.org_id != p.org_id:
        raise HTTPException(status_code=404, detail="key not found")
    from agentguard.server.models import utcnow

    row.revoked_at = utcnow()
    await db.commit()
    await audit.append(db, p.org_id, p.actor, "api_key.revoked", key_id, {"prefix": row.prefix})
    return RedirectResponse("/settings", status_code=303)

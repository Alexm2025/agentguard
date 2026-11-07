"""Simple, non-technical pages: Home, Rules (switches instead of YAML) and adding teammates."""

from __future__ import annotations

import copy
from typing import Any

import yaml
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.core.policy.loader import default_policy_text
from agentguard.server import audit, services
from agentguard.server.auth import SESSION_COOKIE, Principal, get_db
from agentguard.server.dashboard.views import need, render, ui_principal
from agentguard.server.models import ApiKey, Approval, Event, Membership, Policy, User
from agentguard.server.security import hash_password

router = APIRouter(include_in_schema=False)
MAIN_POLICY = "main"

PROTECTIONS: list[dict[str, Any]] = [
    {
        "key": "addresses",
        "icon": "mail",
        "title": "Don't contact people your agent found online",
        "desc": "Stops the agent from emailing, messaging or paying someone whose address came from a web page, "
        "an email or a file - instead of from you.",
        "rules": ["tainted-destination-high", "tainted-destination"],
    },
    {
        "key": "secrets",
        "icon": "key",
        "title": "Never leak passwords and keys",
        "desc": "Blocks any action that would send a password, API key, token or private key anywhere.",
        "rules": ["secrets-to-sink", "secrets-in-url"],
    },
    {
        "key": "hidden",
        "icon": "alert",
        "title": "Watch for hidden instructions",
        "desc": "When the agent reads something that contains instructions aimed at it, risky actions are "
        "stopped and other important ones wait for your OK.",
        "rules": ["injection-steered-critical", "injection-steered-high", "injection-steered-sink"],
    },
    {
        "key": "risky",
        "icon": "trash",
        "title": "Ask before deleting or moving money",
        "desc": "Deleting things, running commands and payments that use details from outside content need a "
        "person's OK first.",
        "rules": ["tainted-critical-action"],
    },
    {
        "key": "links",
        "icon": "globe",
        "title": "Block links that smuggle data out",
        "desc": "Stops the agent from opening web links, suggested by outside content, that carry your data in them.",
        "rules": ["exfil-via-url-params"],
    },
]
WAIT_CHOICES = [(300, "5 minutes"), (3600, "1 hour"), (86_400, "1 day")]


# ---------------------------------------------------------------- home


@router.get("/home")
async def home(request: Request, p: Principal = Depends(ui_principal), db: AsyncSession = Depends(get_db)) -> Response:
    need(p, "events:read")
    m = await services.metrics_summary(db, p.org_id, 24)
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
    total = int(
        (await db.execute(select(func.count()).select_from(Event).where(Event.org_id == p.org_id))).scalar() or 0
    )
    has_key = bool(
        (
            await db.execute(
                select(func.count()).select_from(ApiKey).where(ApiKey.org_id == p.org_id, ApiKey.revoked_at.is_(None))
            )
        ).scalar()
    )
    recent = (
        (
            await db.execute(
                select(Event)
                .where(Event.org_id == p.org_id, Event.type != "tool_result")
                .order_by(Event.timestamp.desc())
                .limit(6)
            )
        )
        .scalars()
        .all()
    )
    user = await db.get(User, p.id)
    first_name = ((user.name if user else "") or p.display).split(" ")[0].split("@")[0]
    return render(
        request,
        "home.html",
        p,
        m=m,
        pending=pending,
        total=total,
        has_key=has_key,
        recent=recent,
        first_name=first_name,
        has_policy=await services.active_policy(db, p.org_id, None) is not None,
    )


# ---------------------------------------------------------------- guide


@router.get("/guide")
async def guide(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    """Plain-language introduction; works signed in (inside the console) or signed out."""
    p: Principal | None = None
    if request.cookies.get(SESSION_COOKIE):
        try:
            p = await ui_principal(request, db)
        except HTTPException:
            p = None
    return render(request, "guide.html", p, signup=request.app.state.settings.allow_signup)


# ---------------------------------------------------------------- rules


async def _live_policy(db: AsyncSession, org_id: str) -> tuple[Policy | None, dict[str, Any]]:
    """The organization-wide policy agents currently receive (what the switches must reflect)."""
    found = await services.active_policy(db, org_id, None)
    if found is None:
        return None, {}
    pol, pv = found
    return pol, yaml.safe_load(pv.yaml) or {}


def _state(data: dict[str, Any]) -> dict[str, Any]:
    by_id = {r.get("id"): r for r in data.get("rules") or [] if isinstance(r, dict)}
    inherits: bool = data.get("extends", "default") == "default"

    def is_on(rid: str) -> bool:
        rule = by_id.get(rid)
        if rule is None:
            return inherits  # inherited from the default policy, or absent from a standalone one
        return rule.get("enabled", True) is not False

    settings = data.get("settings") or {}
    return {
        "on": {pr["key"]: all(is_on(rid) for rid in pr["rules"]) for pr in PROTECTIONS},
        "fail_mode": settings.get("fail_mode", "closed"),
        "wait": int((settings.get("approvals") or {}).get("timeout_seconds", 300)),
    }


@router.get("/rules")
async def rules_page(
    request: Request, p: Principal = Depends(ui_principal), db: AsyncSession = Depends(get_db)
) -> Response:
    need(p, "policies:read")
    pol, data = await _live_policy(db, p.org_id)
    return render(
        request,
        "rules.html",
        p,
        protections=PROTECTIONS,
        state=_state(data),
        waits=WAIT_CHOICES,
        saved=request.query_params.get("saved") == "1",
        policy=pol,
    )


@router.post("/rules")
async def rules_save(
    request: Request, p: Principal = Depends(ui_principal), db: AsyncSession = Depends(get_db)
) -> Response:
    need(p, "policies:write")
    form = await request.form()
    enabled = {pr["key"] for pr in PROTECTIONS if form.get(f"on_{pr['key']}") == "1"}
    fail_mode = "open" if form.get("fail_mode") == "open" else "closed"
    try:
        wait = int(str(form.get("wait", "300")))
    except ValueError:
        wait = 300
    if wait not in {w for w, _ in WAIT_CHOICES}:
        wait = 300

    pol, data = await _live_policy(db, p.org_id)
    data = copy.deepcopy(data)
    if pol is None:
        data = {
            "version": 1,
            "extends": "default",
            "name": MAIN_POLICY,
            "description": "Managed from the Protection rules page.",
        }
    inherits: bool = data.get("extends", "default") == "default"
    default_rules = {r["id"]: r for r in yaml.safe_load(default_policy_text())["rules"]}
    managed = {rid for pr in PROTECTIONS for rid in pr["rules"]}
    rules = [r for r in data.get("rules") or [] if not (isinstance(r, dict) and r.get("id") in managed)]
    for pr in PROTECTIONS:
        on = pr["key"] in enabled
        for rid in pr["rules"]:
            if not on:
                rules.append({**default_rules[rid], "enabled": False})
            elif not inherits:  # a standalone policy needs the rule written out to have it
                rules.append({**default_rules[rid], "enabled": True})
    data["rules"] = rules
    settings = data.setdefault("settings", {})
    settings["fail_mode"] = fail_mode
    settings.setdefault("approvals", {})["timeout_seconds"] = wait
    data.pop("revision", None)
    if pol is None:
        pol = Policy(org_id=p.org_id, name=MAIN_POLICY)
        db.add(pol)
        await db.flush()
    off = [pr["title"] for pr in PROTECTIONS if pr["key"] not in enabled]
    note = "Protection rules: " + (f"turned off {'; '.join(off)}" if off else "all protections on")
    await services.create_policy_version(db, pol, yaml.safe_dump(data, sort_keys=False), p.actor, note[:500])
    return RedirectResponse("/rules?saved=1", status_code=303)


# ---------------------------------------------------------------- teammates


@router.post("/settings/members")
async def add_teammate(
    request: Request,
    email: str = Form(max_length=320),
    name: str = Form(default="", max_length=200),
    role: str = Form(pattern="^(admin|analyst|viewer)$"),
    password: str = Form(max_length=1024),
    p: Principal = Depends(ui_principal),
    db: AsyncSession = Depends(get_db),
) -> Response:
    need(p, "members:manage")
    email = email.strip().lower()
    if "@" not in email or len(password) < 12:
        raise HTTPException(
            status_code=422, detail="Enter a valid email and a temporary password of at least 12 characters."
        )
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if user is None:
        user = User(email=email, name=name.strip(), password_hash=hash_password(password))
        db.add(user)
        await db.flush()
    exists = (
        await db.execute(select(Membership).where(Membership.org_id == p.org_id, Membership.user_id == user.id))
    ).scalar_one_or_none()
    if exists is None:
        db.add(Membership(org_id=p.org_id, user_id=user.id, role=role))
        await db.commit()
        await audit.append(db, p.org_id, p.actor, "member.added", user.id, {"email": email, "role": role})
    return RedirectResponse("/settings?added=1", status_code=303)

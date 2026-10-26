"""Multi-organization administration.

The data model is multi-tenant in every edition (all rows carry ``org_id`` and all queries filter
on it). The community edition provisions a single organization; this module lets platform
administrators (``AGENTGUARD_PLATFORM_ADMINS``, comma-separated emails) create organizations and
lets users who belong to several organizations switch between them.
"""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.server import audit
from agentguard.server.api.routes import set_session_cookie
from agentguard.server.auth import Principal, create_session, current_principal, get_db
from agentguard.server.models import Membership, Organization, User

router = APIRouter(prefix="/api/v1/ee")


def platform_admins() -> set[str]:
    return {e.strip().lower() for e in os.environ.get("AGENTGUARD_PLATFORM_ADMINS", "").split(",") if e.strip()}


class OrgIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9\-]{0,62}$")
    admin_email: str = Field(pattern=r"^[^@\s]{1,64}@[^@\s]{1,255}$")


@router.post("/orgs", status_code=201)
async def create_org(
    body: OrgIn, p: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
    if p.kind != "user" or p.display.lower() not in platform_admins():
        raise HTTPException(status_code=403, detail="platform administrator required")
    if (await db.execute(select(Organization).where(Organization.slug == body.slug))).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="slug exists")
    org = Organization(name=body.name, slug=body.slug, settings={})
    db.add(org)
    user = (await db.execute(select(User).where(User.email == body.admin_email.lower()))).scalar_one_or_none()
    if user is None:
        user = User(email=body.admin_email.lower(), name=body.admin_email.split("@")[0])
        db.add(user)
    await db.flush()
    db.add(Membership(org_id=org.id, user_id=user.id, role="admin"))
    await db.commit()
    await audit.append(db, org.id, p.actor, "org.created", org.id, {"slug": body.slug, "admin": body.admin_email})
    return {"id": org.id, "slug": org.slug}


@router.get("/orgs/mine")
async def my_orgs(
    p: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)
) -> list[dict[str, str]]:
    if p.kind != "user":
        raise HTTPException(status_code=403, detail="user session required")
    rows = (
        await db.execute(
            select(Organization, Membership)
            .join(Membership, Membership.org_id == Organization.id)
            .where(Membership.user_id == p.id)
        )
    ).all()
    return [
        {"id": o.id, "slug": o.slug, "name": o.name, "role": m.role, "current": str(o.id == p.org_id).lower()}
        for o, m in rows
    ]


class SwitchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    org_id: str = Field(max_length=40)


@router.post("/orgs/switch")
async def switch_org(
    body: SwitchIn,
    request: Request,
    response: Response,
    p: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    if p.kind != "user":
        raise HTTPException(status_code=403, detail="user session required")
    mem = (
        await db.execute(select(Membership).where(Membership.user_id == p.id, Membership.org_id == body.org_id))
    ).scalar_one_or_none()
    if mem is None:
        raise HTTPException(status_code=404, detail="not a member of that organization")
    user = await db.get(User, p.id)
    if user is None:  # pragma: no cover
        raise HTTPException(status_code=404, detail="user not found")
    token, ws = await create_session(db, user, body.org_id, request, request.app.state.settings)
    set_session_cookie(response, token, request.app.state.settings)
    await audit.append(db, body.org_id, p.actor, "auth.org_switched", p.id, {"from": p.org_id})
    return {"org_id": body.org_id, "csrf_token": ws.csrf_token}

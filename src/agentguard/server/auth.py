"""Request authentication and role-based access control.

Principals come from either:
* an API key (``X-AgentGuard-Key`` or ``Authorization: Bearer ag_...``) - scopes limit what it can do;
* a browser session cookie (HttpOnly, SameSite=Strict) - the user's role in the org applies, and
  state-changing requests must carry the session's CSRF token (``X-CSRF-Token`` header or
  ``csrf_token`` form field).
"""

from __future__ import annotations

import hmac
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.server.models import ApiKey, Membership, User, WebSession, utcnow
from agentguard.server.security import new_token, sha256
from agentguard.server.settings import ServerSettings

SESSION_COOKIE = "ag_session"
ROLES = ("viewer", "analyst", "admin")

# permission -> minimum role (for users) and required scope (for API keys)
PERMISSIONS: dict[str, tuple[str, str]] = {
    "events:read": ("viewer", "read"),
    "events:write": ("admin", "ingest"),
    "approvals:read": ("viewer", "read"),
    "approvals:create": ("admin", "ingest"),
    "approvals:status": ("viewer", "ingest"),
    "approvals:resolve": ("analyst", "approve"),
    "fp:write": ("analyst", "read"),
    "policies:read": ("viewer", "read"),
    "policies:fetch": ("viewer", "ingest"),
    "policies:write": ("admin", "admin"),
    "projects:read": ("viewer", "read"),
    "projects:write": ("admin", "admin"),
    "keys:manage": ("admin", "admin"),
    "members:manage": ("admin", "admin"),
    "audit:read": ("admin", "admin"),
    "metrics:read": ("viewer", "read"),
    "settings:write": ("admin", "admin"),
}
VALID_SCOPES = frozenset({"ingest", "read", "approve", "admin", "gateway"})


@dataclass
class Principal:
    org_id: str
    kind: str  # user | api_key
    id: str
    display: str
    role: str | None = None
    scopes: frozenset[str] = field(default_factory=frozenset)
    project_id: str | None = None
    csrf_token: str | None = None

    def can(self, permission: str) -> bool:
        min_role, scope = PERMISSIONS[permission]
        if self.kind == "user":
            return self.role is not None and ROLES.index(self.role) >= ROLES.index(min_role)
        return "admin" in self.scopes or scope in self.scopes

    @property
    def actor(self) -> str:
        return f"{self.kind}:{self.display}"


def _client_ip(request: Request, settings: ServerSettings) -> str:
    if settings.trust_proxy_headers and (fwd := request.headers.get("x-forwarded-for")):
        return fwd.split(",")[0].strip()[:64]
    return (request.client.host if request.client else "")[:64]


def extract_api_key(request: Request) -> str | None:
    key = request.headers.get("x-agentguard-key")
    if not key:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer ag_"):
            key = auth[7:].strip()
    return key or None


async def principal_from_key(db: AsyncSession, key: str) -> Principal | None:
    row = (await db.execute(select(ApiKey).where(ApiKey.key_hash == sha256(key)))).scalar_one_or_none()
    if row is None or row.revoked_at is not None:
        return None
    if row.expires_at is not None and _aware(row.expires_at) < utcnow():
        return None
    now = utcnow()
    if row.last_used_at is None or _aware(row.last_used_at) < now - timedelta(minutes=5):
        await db.execute(update(ApiKey).where(ApiKey.id == row.id).values(last_used_at=now))
        await db.commit()
    return Principal(
        row.org_id,
        "api_key",
        row.id,
        f"{row.name} ({row.prefix}...)",
        None,
        frozenset(row.scopes or []),
        row.project_id,
    )


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


async def principal_from_session(db: AsyncSession, token: str) -> Principal | None:
    ws = (await db.execute(select(WebSession).where(WebSession.id == sha256(token)))).scalar_one_or_none()
    if ws is None or _aware(ws.expires_at) < utcnow():
        return None
    user = await db.get(User, ws.user_id)
    if user is None or not user.is_active:
        return None
    mem = (
        await db.execute(select(Membership).where(Membership.org_id == ws.org_id, Membership.user_id == user.id))
    ).scalar_one_or_none()
    if mem is None:
        return None
    return Principal(ws.org_id, "user", user.id, user.email, mem.role, frozenset(), None, ws.csrf_token)


async def create_session(
    db: AsyncSession, user: User, org_id: str, request: Request, settings: ServerSettings
) -> tuple[str, WebSession]:
    token = new_token()
    ws = WebSession(
        id=sha256(token),
        user_id=user.id,
        org_id=org_id,
        csrf_token=new_token(),
        expires_at=utcnow() + timedelta(hours=settings.session_ttl_hours),
        ip=_client_ip(request, settings),
        user_agent=request.headers.get("user-agent", "")[:300],
    )
    db.add(ws)
    user.last_login_at = utcnow()
    await db.commit()
    return token, ws


UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


async def resolve_principal(request: Request, db: AsyncSession) -> Principal | None:
    key = extract_api_key(request)
    if key:
        return await principal_from_key(db, key)
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    p = await principal_from_session(db, token)
    if p is not None and request.method in UNSAFE_METHODS:
        sent = request.headers.get("x-csrf-token")
        if sent is None and request.headers.get("content-type", "").startswith(
            ("application/x-www-form-urlencoded", "multipart/form-data")
        ):
            form = await request.form()
            sent = str(form.get("csrf_token") or "")
        if not sent or not p.csrf_token or not hmac.compare_digest(sent, p.csrf_token):
            raise HTTPException(status_code=403, detail="CSRF token missing or invalid")
    return p


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    async with request.app.state.database.sessionmaker() as session:
        yield session


async def current_principal(request: Request, db: AsyncSession = Depends(get_db)) -> Principal:
    p = getattr(request.state, "principal", None)
    if p is None:
        p = await resolve_principal(request, db)
        request.state.principal = p
    if p is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return p


def require(permission: str):  # type: ignore[no-untyped-def]
    async def dep(p: Principal = Depends(current_principal)) -> Principal:
        if not p.can(permission):
            raise HTTPException(status_code=403, detail=f"missing permission {permission}")
        return p

    return dep

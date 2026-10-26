"""OpenID Connect single sign-on (Authorization Code flow with PKCE).

Environment:
  AGENTGUARD_OIDC_ISSUER          https://login.example.com/realms/acme
  AGENTGUARD_OIDC_CLIENT_ID / AGENTGUARD_OIDC_CLIENT_SECRET
  AGENTGUARD_OIDC_ORG_SLUG        organization users are provisioned into (default: default)
  AGENTGUARD_OIDC_DEFAULT_ROLE    role for new users (default: viewer)
  AGENTGUARD_OIDC_ROLE_CLAIM      claim holding groups/roles (e.g. groups)
  AGENTGUARD_OIDC_ROLE_MAP        JSON: {"agentguard-admins": "admin", "secops": "analyst"}
  AGENTGUARD_OIDC_ALLOWED_DOMAINS comma-separated email domains allowed to sign in (optional)
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
from authlib.jose import JsonWebKey, JsonWebToken
from authlib.jose.errors import JoseError
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.server import audit
from agentguard.server.api.routes import set_session_cookie
from agentguard.server.auth import create_session, get_db
from agentguard.server.models import Membership, Organization, User
from agentguard.server.security import sign, unsign

router = APIRouter(include_in_schema=False)
STATE_COOKIE = "ag_oidc"
ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}


@dataclass
class OidcConfig:
    issuer: str
    client_id: str
    client_secret: str | None
    org_slug: str = "default"
    default_role: str = "viewer"
    role_claim: str | None = None
    role_map: dict[str, str] = field(default_factory=dict)
    allowed_domains: list[str] = field(default_factory=list)
    scopes: str = "openid email profile"

    @classmethod
    def from_env(cls) -> OidcConfig | None:
        issuer = os.environ.get("AGENTGUARD_OIDC_ISSUER")
        client_id = os.environ.get("AGENTGUARD_OIDC_CLIENT_ID")
        if not issuer or not client_id:
            return None
        role_map = json.loads(os.environ.get("AGENTGUARD_OIDC_ROLE_MAP", "{}"))
        if any(v not in ROLE_RANK for v in role_map.values()):
            raise ValueError("AGENTGUARD_OIDC_ROLE_MAP values must be admin, analyst or viewer")
        return cls(
            issuer=issuer.rstrip("/"),
            client_id=client_id,
            client_secret=os.environ.get("AGENTGUARD_OIDC_CLIENT_SECRET"),
            org_slug=os.environ.get("AGENTGUARD_OIDC_ORG_SLUG", "default"),
            default_role=os.environ.get("AGENTGUARD_OIDC_DEFAULT_ROLE", "viewer"),
            role_claim=os.environ.get("AGENTGUARD_OIDC_ROLE_CLAIM"),
            role_map=role_map,
            allowed_domains=[
                d.strip().lower() for d in os.environ.get("AGENTGUARD_OIDC_ALLOWED_DOMAINS", "").split(",") if d.strip()
            ],
        )


class OidcClient:
    def __init__(self, cfg: OidcConfig, http: httpx.AsyncClient | None = None) -> None:
        self.cfg = cfg
        self.http = http or httpx.AsyncClient(timeout=10)
        self._meta: dict[str, Any] | None = None
        self._jwks: Any = None
        self._jwks_at = 0.0

    async def metadata(self) -> dict[str, Any]:
        if self._meta is None:
            r = await self.http.get(f"{self.cfg.issuer}/.well-known/openid-configuration")
            r.raise_for_status()
            meta = r.json()
            if meta.get("issuer", "").rstrip("/") != self.cfg.issuer:
                raise HTTPException(status_code=502, detail="OIDC issuer mismatch in discovery document")
            self._meta = meta
        return self._meta

    async def jwks(self, force: bool = False) -> Any:
        if self._jwks is None or force or time.time() - self._jwks_at > 3600:
            r = await self.http.get((await self.metadata())["jwks_uri"])
            r.raise_for_status()
            self._jwks = JsonWebKey.import_key_set(r.json())
            self._jwks_at = time.time()
        return self._jwks

    async def exchange(self, code: str, redirect_uri: str, verifier: str) -> dict[str, Any]:
        meta = await self.metadata()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
            "client_id": self.cfg.client_id,
        }
        if self.cfg.client_secret:  # confidential client: client_secret_basic
            r = await self.http.post(
                meta["token_endpoint"], data=data, auth=(self.cfg.client_id, self.cfg.client_secret)
            )
        else:  # public client: PKCE only
            r = await self.http.post(meta["token_endpoint"], data=data)
        if r.status_code != 200:
            raise HTTPException(status_code=401, detail="OIDC token exchange failed")
        return r.json()  # type: ignore[no-any-return]

    async def verify_id_token(self, token: str, nonce: str) -> dict[str, Any]:
        jwt = JsonWebToken(["RS256", "RS384", "RS512", "ES256", "ES384", "PS256"])
        for force in (False, True):  # retry once with refreshed keys (key rotation)
            try:
                claims = jwt.decode(
                    token,
                    await self.jwks(force=force),
                    claims_options={
                        "iss": {"essential": True, "value": self.cfg.issuer},
                        "aud": {"essential": True, "value": self.cfg.client_id},
                        "exp": {"essential": True},
                        "nonce": {"essential": True, "value": nonce},
                    },
                )
                claims.validate(leeway=60)
                return dict(claims)
            except JoseError:
                if force:
                    raise HTTPException(status_code=401, detail="invalid ID token") from None
        raise HTTPException(status_code=401, detail="invalid ID token")


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


def _redirect_uri(request: Request) -> str:
    return str(request.app.state.settings.public_url).rstrip("/") + "/auth/oidc/callback"


@router.get("/auth/oidc/login")
async def oidc_login(request: Request) -> Response:
    client: OidcClient = request.app.state.oidc
    meta = await client.metadata()
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    verifier, challenge = _pkce()
    params = httpx.QueryParams(
        {
            "response_type": "code",
            "client_id": client.cfg.client_id,
            "redirect_uri": _redirect_uri(request),
            "scope": client.cfg.scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    resp = RedirectResponse(f"{meta['authorization_endpoint']}?{params}", status_code=302)
    settings = request.app.state.settings
    blob = sign({"s": state, "n": nonce, "v": verifier}, settings.secret_key, 600)
    # SameSite=Lax is required: the IdP redirects back with a top-level cross-site GET.
    resp.set_cookie(
        STATE_COOKIE,
        blob,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
        max_age=600,
        path="/auth/oidc",
    )
    return resp


def _role_for(cfg: OidcConfig, claims: dict[str, Any]) -> str:
    role = cfg.default_role
    if cfg.role_claim:
        values = claims.get(cfg.role_claim) or []
        values = [values] if isinstance(values, str) else values
        for v in values:
            mapped = cfg.role_map.get(str(v))
            if mapped and ROLE_RANK[mapped] > ROLE_RANK[role]:
                role = mapped
    return role


@router.get("/auth/oidc/callback")
async def oidc_callback(
    request: Request, code: str = "", state: str = "", error: str = "", db: AsyncSession = Depends(get_db)
) -> Response:
    client: OidcClient = request.app.state.oidc
    settings = request.app.state.settings
    if error:
        raise HTTPException(status_code=401, detail="sign-in was cancelled or failed at the identity provider")
    blob = unsign(request.cookies.get(STATE_COOKIE, ""), settings.secret_key)
    if blob is None or not secrets.compare_digest(str(blob.get("s")), state) or not code:
        raise HTTPException(status_code=400, detail="invalid OIDC state")
    tokens = await client.exchange(code, _redirect_uri(request), str(blob["v"]))
    claims = await client.verify_id_token(str(tokens.get("id_token", "")), str(blob["n"]))
    email = str(claims.get("email") or "").lower()
    if not email or claims.get("email_verified") is False:
        raise HTTPException(status_code=403, detail="the identity provider did not return a verified email")
    if client.cfg.allowed_domains and email.rsplit("@", 1)[-1] not in client.cfg.allowed_domains:
        raise HTTPException(status_code=403, detail="email domain not allowed")
    subject = f"{client.cfg.issuer}|{claims['sub']}"

    org = (await db.execute(select(Organization).where(Organization.slug == client.cfg.org_slug))).scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=500, detail="OIDC organization is not configured")
    user = (await db.execute(select(User).where(User.oidc_subject == subject))).scalar_one_or_none()
    if user is None:
        user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
        if user is None:
            user = User(email=email, name=str(claims.get("name") or email), oidc_subject=subject)
            db.add(user)
            await db.flush()
        elif user.oidc_subject is None:
            user.oidc_subject = subject
        elif user.oidc_subject != subject:
            raise HTTPException(status_code=403, detail="email is linked to a different identity")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="account disabled")
    role = _role_for(client.cfg, claims)
    mem = (
        await db.execute(select(Membership).where(Membership.org_id == org.id, Membership.user_id == user.id))
    ).scalar_one_or_none()
    if mem is None:
        db.add(Membership(org_id=org.id, user_id=user.id, role=role))
    elif client.cfg.role_claim:
        mem.role = role  # IdP is the source of truth when a role claim is configured
    await db.commit()
    token, _ = await create_session(db, user, org.id, request, settings)
    await audit.append(db, org.id, f"user:{email}", "auth.login", user.id, {"via": "oidc", "role": role})
    resp = RedirectResponse("/events", status_code=303)
    set_session_cookie(resp, token, settings)
    resp.delete_cookie(STATE_COOKIE, path="/auth/oidc")
    return resp

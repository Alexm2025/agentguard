"""OIDC login against a local test identity provider (real protocol: discovery, JWKS, PKCE,
RS256-signed ID tokens)."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import urllib.parse
from pathlib import Path

import httpx
import pytest

pytest.importorskip("agentguard_ee")
from authlib.jose import JsonWebKey, jwt
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Route

from agentguard.core.ratelimit import MemoryRateLimiter
from agentguard.server.app import bootstrap, create_app
from agentguard.server.db import Database
from agentguard.server.settings import ServerSettings
from agentguard_ee.oidc import OidcClient, OidcConfig

ISSUER = "http://idp.test"


class LocalIdP:
    def __init__(
        self, email: str = "alice@acme.test", groups: list[str] | None = None, aud: str = "agentguard"
    ) -> None:
        self.key = JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": "k1"})
        self.codes: dict[str, dict] = {}
        self.email, self.groups, self.aud = email, groups or [], aud

    def app(self) -> Starlette:
        async def discovery(_: Request) -> JSONResponse:
            return JSONResponse(
                {
                    "issuer": ISSUER,
                    "authorization_endpoint": f"{ISSUER}/authorize",
                    "token_endpoint": f"{ISSUER}/token",
                    "jwks_uri": f"{ISSUER}/jwks",
                }
            )

        async def jwks(_: Request) -> JSONResponse:
            return JSONResponse({"keys": [self.key.as_dict(is_private=False)]})

        async def authorize(r: Request) -> RedirectResponse:
            q = r.query_params
            assert q["response_type"] == "code" and q["code_challenge_method"] == "S256"
            code = secrets.token_urlsafe(16)
            self.codes[code] = {
                "nonce": q["nonce"],
                "challenge": q["code_challenge"],
                "redirect_uri": q["redirect_uri"],
            }
            return RedirectResponse(
                f"{q['redirect_uri']}?{urllib.parse.urlencode({'code': code, 'state': q['state']})}"
            )

        async def token(r: Request) -> JSONResponse:
            form = await r.form()
            data = self.codes.pop(str(form["code"]), None)
            if data is None:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            verifier = str(form["code_verifier"])
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
            if challenge != data["challenge"] or form["redirect_uri"] != data["redirect_uri"]:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            now = int(time.time())
            claims = {
                "iss": ISSUER,
                "aud": self.aud,
                "sub": "user-123",
                "email": self.email,
                "email_verified": True,
                "name": "Alice",
                "nonce": data["nonce"],
                "iat": now,
                "exp": now + 300,
                "groups": self.groups,
            }
            id_token = jwt.encode({"alg": "RS256", "kid": "k1"}, claims, self.key).decode()
            return JSONResponse({"access_token": "at", "token_type": "Bearer", "id_token": id_token})

        return Starlette(
            routes=[
                Route("/.well-known/openid-configuration", discovery),
                Route("/jwks", jwks),
                Route("/authorize", authorize),
                Route("/token", token, methods=["POST"]),
            ]
        )


async def make_stack(tmp_path: Path, idp: LocalIdP, monkeypatch: pytest.MonkeyPatch, **env: str):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("AGENTGUARD_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("AGENTGUARD_OIDC_CLIENT_ID", "agentguard")
    monkeypatch.setenv("AGENTGUARD_OIDC_CLIENT_SECRET", "s3cret")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    settings = ServerSettings(
        env="test",
        database_url=f"sqlite+aiosqlite:///{(tmp_path / 'o.db').as_posix()}",
        secret_key="x" * 48,
        bootstrap_admin_email="root@acme.test",
        bootstrap_admin_password="correct horse battery staple",
        public_url="http://cp.test",
    )
    db = Database(settings.database_url)
    await db.create_all()
    await bootstrap(db, settings)
    app = create_app(settings, database=db, create_schema=False, rate_limiter=MemoryRateLimiter())
    app.state.oidc = OidcClient(
        OidcConfig.from_env(), http=httpx.AsyncClient(transport=httpx.ASGITransport(app=idp.app()))
    )  # type: ignore[arg-type]
    return app


async def browser_login(app, idp: LocalIdP) -> httpx.Response:  # type: ignore[no-untyped-def]
    browser = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://cp.test")
    idp_browser = httpx.AsyncClient(transport=httpx.ASGITransport(app=idp.app()), base_url=ISSUER)
    r = await browser.get("/auth/oidc/login")
    assert r.status_code == 302 and r.headers["location"].startswith(f"{ISSUER}/authorize")
    r2 = await idp_browser.get(r.headers["location"])
    callback = r2.headers["location"]
    r3 = await browser.get(callback.replace("http://cp.test", ""))
    r3.browser = browser  # type: ignore[attr-defined]
    return r3


async def test_oidc_login_provisions_user_with_mapped_role(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    idp = LocalIdP(groups=["secops"])
    app = await make_stack(
        tmp_path,
        idp,
        monkeypatch,
        AGENTGUARD_OIDC_ROLE_CLAIM="groups",
        AGENTGUARD_OIDC_ROLE_MAP=json.dumps({"secops": "analyst"}),
    )
    async with app.router.lifespan_context(app):
        r = await browser_login(app, idp)
        assert r.status_code == 303 and r.headers["location"] == "/events"
        me = (await r.browser.get("/api/v1/auth/me")).json()  # type: ignore[attr-defined]
        assert me["display"] == "alice@acme.test" and me["role"] == "analyst"
        page = await r.browser.get("/login")  # type: ignore[attr-defined]
        assert "Sign in with SSO" in page.text


async def test_oidc_rejects_tampered_state_wrong_audience_and_domain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    idp = LocalIdP(aud="someone-else")
    app = await make_stack(tmp_path, idp, monkeypatch)
    async with app.router.lifespan_context(app):
        r = await browser_login(app, idp)
        assert r.status_code == 401  # aud mismatch
        browser = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://cp.test")
        await browser.get("/auth/oidc/login")
        assert (await browser.get("/auth/oidc/callback?code=x&state=forged")).status_code == 400

    idp2 = LocalIdP(email="mallory@evil.test")
    app2 = await make_stack(
        tmp_path / "2" if (tmp_path / "2").mkdir() is None else tmp_path,
        idp2,
        monkeypatch,
        AGENTGUARD_OIDC_ALLOWED_DOMAINS="acme.test",
    )
    async with app2.router.lifespan_context(app2):
        r = await browser_login(app2, idp2)
        assert r.status_code == 403

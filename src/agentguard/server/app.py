"""Control-plane application factory."""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from importlib.metadata import entry_points
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from starlette.middleware.base import BaseHTTPMiddleware

from agentguard import __version__
from agentguard.core.ratelimit import MemoryRateLimiter, RateLimiter
from agentguard.server import audit
from agentguard.server.auth import extract_api_key
from agentguard.server.db import Database
from agentguard.server.models import Membership, Organization, User
from agentguard.server.security import hash_password, sha256
from agentguard.server.services import webhook_notifier
from agentguard.server.settings import ServerSettings, get_settings

log = logging.getLogger(__name__)
MAX_REQUEST_BYTES = 12 * 1024 * 1024
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"
)


class SecurityHeaders(BaseHTTPMiddleware):
    def __init__(self, app: Any, settings: ServerSettings) -> None:
        super().__init__(app)
        self.hsts = settings.secure_cookies

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_REQUEST_BYTES:
            return JSONResponse({"detail": "request too large"}, status_code=413)
        response = await call_next(request)
        h = response.headers
        h.setdefault("content-security-policy", CSP)
        h.setdefault("x-content-type-options", "nosniff")
        h.setdefault("x-frame-options", "DENY")
        h.setdefault("referrer-policy", "no-referrer")
        h.setdefault("permissions-policy", "camera=(), microphone=(), geolocation=()")
        h.setdefault("cross-origin-opener-policy", "same-origin")
        if request.url.path.startswith("/api/"):
            h.setdefault("cache-control", "no-store")
        if self.hsts:
            h.setdefault("strict-transport-security", "max-age=63072000; includeSubDomains")
        return response


class RateLimit(BaseHTTPMiddleware):
    def __init__(self, app: Any, limiter: RateLimiter, per_minute: int, trust_proxy: bool) -> None:
        super().__init__(app)
        self.limiter, self.per_minute, self.trust_proxy = limiter, per_minute, trust_proxy

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        if request.url.path.startswith("/api/"):
            key = extract_api_key(request)
            if key:
                ident = "k:" + sha256(key)[:24]
            else:
                ip = request.client.host if request.client else "?"
                if self.trust_proxy and (fwd := request.headers.get("x-forwarded-for")):
                    ip = fwd.split(",")[0].strip()
                ident = "ip:" + ip
            import asyncio

            ok = await asyncio.to_thread(self.limiter.hit, f"api:{ident}", self.per_minute, 60)
            if not ok:
                return JSONResponse({"detail": "rate limit exceeded"}, status_code=429, headers={"retry-after": "60"})
        return await call_next(request)


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60] or "org"


async def bootstrap(db: Database, settings: ServerSettings) -> None:
    """Create the first organisation and admin from env vars if the database has no users."""
    if not settings.bootstrap_admin_email or not settings.bootstrap_admin_password:
        return
    async with db.sessionmaker() as s:
        if (await s.execute(select(func.count()).select_from(User))).scalar():
            return
        org = Organization(name="Default", slug="default", settings={})
        user = User(
            email=settings.bootstrap_admin_email.lower(),
            name="Admin",
            password_hash=hash_password(settings.bootstrap_admin_password),
        )
        s.add_all([org, user])
        await s.flush()
        s.add(Membership(org_id=org.id, user_id=user.id, role="admin"))
        await s.commit()
        await audit.append(s, org.id, "system", "bootstrap.admin_created", user.id, {"email": user.email})
        log.info("bootstrapped organisation %s with admin %s", org.slug, user.email)


def create_app(
    settings: ServerSettings | None = None,
    *,
    database: Database | None = None,
    create_schema: bool | None = None,
    rate_limiter: RateLimiter | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    db = database or Database(settings.database_url)
    if rate_limiter is None:
        if settings.redis_url:
            from agentguard.server.ratelimit import RedisRateLimiter

            rate_limiter = RedisRateLimiter.from_url(settings.redis_url)
        else:
            rate_limiter = MemoryRateLimiter()
    auto_schema = create_schema if create_schema is not None else settings.database_url.startswith("sqlite")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if auto_schema:
            await db.create_all()
        await bootstrap(db, settings)
        yield
        await db.dispose()

    app = FastAPI(
        title="AgentGuard control plane",
        version=__version__,
        lifespan=lifespan,
        docs_url=None if settings.production else "/api/docs",
        redoc_url=None,
        openapi_url=None if settings.production else "/api/openapi.json",
    )
    app.state.settings = settings
    app.state.database = db
    app.state.rate_limiter = rate_limiter
    app.state.approval_notifiers = [webhook_notifier]
    app.state.event_forwarders = []
    app.state.features = {"edition": "community"}

    app.add_middleware(
        RateLimit,
        limiter=rate_limiter,
        per_minute=settings.api_rate_limit,
        trust_proxy=settings.trust_proxy_headers,
    )
    if settings.allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.allowed_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["content-type", "x-csrf-token", "x-agentguard-key", "authorization"],
        )
    app.add_middleware(SecurityHeaders, settings=settings)

    from agentguard.server.api.routes import router
    from agentguard.server.dashboard.views import router as dashboard_router
    from agentguard.server.dashboard.views import static_app

    app.include_router(router)
    app.include_router(dashboard_router)
    app.mount("/static", static_app(), name="static")

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/readyz", include_in_schema=False)
    async def readyz() -> Response:
        try:
            async with db.sessionmaker() as s:
                await s.execute(select(1))
        except Exception:
            return JSONResponse({"status": "database unavailable"}, status_code=503)
        return JSONResponse({"status": "ready"})

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse({"detail": "internal server error"}, status_code=500)

    _load_plugins(app)
    return app


def _load_plugins(app: FastAPI) -> None:
    """Enterprise features (ee/) register through the ``agentguard.plugins`` entry point."""
    for ep in entry_points(group="agentguard.plugins"):
        try:
            ep.load()(app)
            log.info("loaded plugin %s", ep.name)
        except Exception:
            log.exception("failed to load plugin %s", ep.name)

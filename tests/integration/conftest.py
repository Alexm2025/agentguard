"""Control-plane fixtures. Runs on SQLite by default; set AGENTGUARD_TEST_DATABASE_URL
(postgresql+psycopg://...) to also run against Postgres (CI does this with a service container)."""

from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

from agentguard.core.ratelimit import MemoryRateLimiter
from agentguard.server.app import bootstrap, create_app
from agentguard.server.db import Database
from agentguard.server.models import Base, Membership, Organization, User
from agentguard.server.security import hash_password
from agentguard.server.settings import ServerSettings

ADMIN_EMAIL, ADMIN_PW = "admin@acme.test", "correct horse battery staple"
PG_URL = os.environ.get("AGENTGUARD_TEST_DATABASE_URL")

if sys.platform == "win32" and PG_URL:
    import asyncio

    # psycopg's async mode cannot use the proactor loop (CI runs on Linux; this is for local runs).
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())  # type: ignore[attr-defined]
DB_PARAMS = ["sqlite"] + (["postgres"] if PG_URL else [])


@dataclass
class Stack:
    app: object
    db: Database
    client: httpx.AsyncClient
    settings: ServerSettings

    async def login(self, email: str = ADMIN_EMAIL, password: str = ADMIN_PW) -> httpx.AsyncClient:
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://cp.test")
        r = await c.post("/api/v1/auth/login", json={"email": email, "password": password})
        assert r.status_code == 200, r.text
        c.headers["x-csrf-token"] = r.json()["csrf_token"]
        return c

    async def add_user(self, email: str, role: str, org_slug: str = "default") -> None:
        from sqlalchemy import select

        async with self.db.sessionmaker() as s:
            org = (await s.execute(select(Organization).where(Organization.slug == org_slug))).scalar_one_or_none()
            if org is None:
                org = Organization(name=org_slug, slug=org_slug, settings={})
                s.add(org)
                await s.flush()
            u = User(email=email, password_hash=hash_password(ADMIN_PW))
            s.add(u)
            await s.flush()
            s.add(Membership(org_id=org.id, user_id=u.id, role=role))
            await s.commit()

    async def key(self, scopes: list[str], client: httpx.AsyncClient | None = None) -> str:
        c = client or await self.login()
        r = await c.post("/api/v1/api-keys", json={"name": "k", "scopes": scopes})
        assert r.status_code == 201, r.text
        return str(r.json()["key"])


@pytest.fixture(params=DB_PARAMS)
async def stack(request: pytest.FixtureRequest, tmp_path: Path) -> AsyncIterator[Stack]:
    url = f"sqlite+aiosqlite:///{(tmp_path / 'cp.db').as_posix()}" if request.param == "sqlite" else str(PG_URL)
    settings = ServerSettings(
        env="test",
        database_url=url,
        secret_key="s" * 48,
        service_token="svc-token-123456",
        bootstrap_admin_email=ADMIN_EMAIL,
        bootstrap_admin_password=ADMIN_PW,
        public_url="http://cp.test",
        api_rate_limit=10_000,
    )
    db = Database(url)
    if request.param == "postgres":
        async with db.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    await db.create_all()
    await bootstrap(db, settings)
    app = create_app(settings, database=db, create_schema=False, rate_limiter=MemoryRateLimiter())
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://cp.test")
    yield Stack(app, db, client, settings)
    await client.aclose()
    await db.dispose()

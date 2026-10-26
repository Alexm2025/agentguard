"""Async database engine and session factory."""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine


class Database:
    def __init__(self, url: str, *, echo: bool = False) -> None:
        kwargs: dict[str, object] = {"echo": echo, "pool_pre_ping": True}
        if url.startswith("sqlite"):
            kwargs.pop("pool_pre_ping")
        self.url = url
        self.engine: AsyncEngine = create_async_engine(url, **kwargs)
        if url.startswith("sqlite"):

            @event.listens_for(self.engine.sync_engine, "connect")
            def _sqlite_pragmas(dbapi_conn, _record):  # type: ignore[no-untyped-def]
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA foreign_keys=ON")
                cur.execute("PRAGMA journal_mode=WAL")
                cur.close()

        self.sessionmaker = async_sessionmaker(self.engine, expire_on_commit=False)

    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.sessionmaker() as s:
            yield s

    async def create_all(self) -> None:
        from agentguard.server.models import Base

        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def dispose(self) -> None:
        await self.engine.dispose()

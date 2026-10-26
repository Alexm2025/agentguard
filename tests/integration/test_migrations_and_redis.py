from __future__ import annotations

import os
from pathlib import Path

import pytest

from agentguard.server.migrations import alembic_config, upgrade


def test_migrations_match_models(tmp_path: Path) -> None:
    """Applying all migrations yields exactly the schema described by the models."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext
    from sqlalchemy import create_engine

    from agentguard.server.models import Base

    db = tmp_path / "m.db"
    upgrade(f"sqlite+aiosqlite:///{db.as_posix()}")
    engine = create_engine(f"sqlite:///{db.as_posix()}")
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []
    assert alembic_config("x").get_main_option("script_location")


@pytest.mark.integration
def test_redis_rate_limiter() -> None:
    url = os.environ.get("AGENTGUARD_TEST_REDIS_URL")
    if not url:
        pytest.skip("AGENTGUARD_TEST_REDIS_URL not set")
    from agentguard.server.ratelimit import RedisRateLimiter

    rl = RedisRateLimiter.from_url(url)
    key = f"test-{os.getpid()}"
    assert [rl.hit(key, 3, 5) for _ in range(4)] == [True, True, True, False]


def test_redis_rate_limiter_fail_modes() -> None:
    from agentguard.server.ratelimit import RedisRateLimiter

    class Broken:
        def register_script(self, _):  # type: ignore[no-untyped-def]
            def run(**kw):  # type: ignore[no-untyped-def]
                raise ConnectionError("down")

            return run

    assert RedisRateLimiter(Broken()).hit("k", 1, 1) is True
    assert RedisRateLimiter(Broken(), fail_open=False).hit("k", 1, 1) is False

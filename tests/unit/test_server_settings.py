from __future__ import annotations

import pytest

from agentguard.server.settings import get_settings, normalize_database_url


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("postgres://u:p@h:5432/db", "postgresql+psycopg://u:p@h:5432/db"),
        ("postgresql://u:p@h/db", "postgresql+psycopg://u:p@h/db"),
        ("postgresql+psycopg://u@h/db", "postgresql+psycopg://u@h/db"),
        ("sqlite+aiosqlite:///./x.db", "sqlite+aiosqlite:///./x.db"),
    ],
)
def test_normalize_database_url(raw: str, expected: str) -> None:
    assert normalize_database_url(raw) == expected


def test_platform_env_fallbacks(monkeypatch: pytest.MonkeyPatch) -> None:
    for k in ("AGENTGUARD_DATABASE_URL", "AGENTGUARD_PUBLIC_URL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgres://a:b@db/x")
    monkeypatch.setenv("RENDER_EXTERNAL_URL", "https://agentguard.onrender.com")
    monkeypatch.setenv("AGENTGUARD_ALLOW_SIGNUP", "true")
    get_settings.cache_clear()
    try:
        s = get_settings()
        assert s.database_url == "postgresql+psycopg://a:b@db/x"
        assert s.public_url == "https://agentguard.onrender.com" and s.secure_cookies and s.allow_signup
    finally:
        get_settings.cache_clear()

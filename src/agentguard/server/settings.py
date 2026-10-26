"""Server configuration from environment variables (optionally a ``.env``-style file).

| Variable | Default | Notes |
|---|---|---|
| ``AGENTGUARD_ENV`` | ``development`` | ``production`` enforces a secret key, secure cookies, no bootstrap password in logs |
| ``AGENTGUARD_DATABASE_URL`` | ``sqlite+aiosqlite:///./agentguard.db`` | Postgres: ``postgresql+psycopg://user:pass@host/db`` |
| ``AGENTGUARD_REDIS_URL`` | unset | enables Redis rate limiting / approval pub-sub |
| ``AGENTGUARD_SECRET_KEY`` | random (dev only) | >= 32 bytes; signs CSRF and webhook tokens |
| ``AGENTGUARD_SERVICE_TOKEN`` | unset | bearer token gateways use for key introspection |
| ``AGENTGUARD_ALLOWED_ORIGINS`` | empty | comma-separated CORS origins |
| ``AGENTGUARD_PUBLIC_URL`` | ``http://localhost:8000`` | used in links (approval webhooks, Slack, OIDC redirect) |
| ``AGENTGUARD_SESSION_TTL_HOURS`` | ``12`` | |
| ``AGENTGUARD_BOOTSTRAP_ADMIN_EMAIL`` / ``_PASSWORD`` | unset | creates the first org + admin on startup if no users exist |
| ``AGENTGUARD_EVENT_RETENTION_DAYS`` | ``90`` | events older than this are deleted by ``agentguard server prune`` |
"""

from __future__ import annotations

import logging
import os
import secrets
from functools import lru_cache

from pydantic import BaseModel, Field, field_validator

log = logging.getLogger(__name__)


def _env(name: str, default: str | None = None) -> str | None:
    file_var = os.environ.get(f"{name}_FILE")  # Docker/K8s secrets mounted as files
    if file_var and os.path.exists(file_var):
        with open(file_var, encoding="utf-8") as fh:
            return fh.read().strip()
    return os.environ.get(name, default)


class ServerSettings(BaseModel):
    env: str = "development"
    database_url: str = "sqlite+aiosqlite:///./agentguard.db"
    redis_url: str | None = None
    secret_key: str = Field(min_length=32)
    service_token: str | None = None
    allowed_origins: list[str] = Field(default_factory=list)
    public_url: str = "http://localhost:8000"
    session_ttl_hours: float = 12.0
    bootstrap_admin_email: str | None = None
    bootstrap_admin_password: str | None = None
    event_retention_days: int = 90
    login_rate_limit: int = 10  # attempts per 5 minutes per IP+email
    api_rate_limit: int = 600  # requests per minute per principal
    max_events_per_batch: int = 500
    trust_proxy_headers: bool = False

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def _split(cls, v: object) -> object:
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    @property
    def production(self) -> bool:
        return self.env == "production"

    @property
    def secure_cookies(self) -> bool:
        return self.production or self.public_url.startswith("https://")


def _split_origins(value: str) -> list[str]:
    return [o.strip() for o in value.split(",") if o.strip()]


@lru_cache(maxsize=1)
def get_settings() -> ServerSettings:
    env = _env("AGENTGUARD_ENV", "development") or "development"
    secret = _env("AGENTGUARD_SECRET_KEY")
    if not secret:
        if env == "production":
            raise RuntimeError("AGENTGUARD_SECRET_KEY must be set (>= 32 chars) in production")
        secret = secrets.token_urlsafe(48)
        log.warning("AGENTGUARD_SECRET_KEY not set; using an ephemeral key (sessions reset on restart)")
    return ServerSettings(
        env=env,
        database_url=_env("AGENTGUARD_DATABASE_URL", "sqlite+aiosqlite:///./agentguard.db") or "",
        redis_url=_env("AGENTGUARD_REDIS_URL"),
        secret_key=secret,
        service_token=_env("AGENTGUARD_SERVICE_TOKEN"),
        allowed_origins=_split_origins(_env("AGENTGUARD_ALLOWED_ORIGINS", "") or ""),
        public_url=_env("AGENTGUARD_PUBLIC_URL", "http://localhost:8000") or "",
        session_ttl_hours=float(_env("AGENTGUARD_SESSION_TTL_HOURS", "12") or 12),
        bootstrap_admin_email=_env("AGENTGUARD_BOOTSTRAP_ADMIN_EMAIL"),
        bootstrap_admin_password=_env("AGENTGUARD_BOOTSTRAP_ADMIN_PASSWORD"),
        event_retention_days=int(_env("AGENTGUARD_EVENT_RETENTION_DAYS", "90") or 90),
        trust_proxy_headers=(_env("AGENTGUARD_TRUST_PROXY_HEADERS", "false") or "").lower() == "true",
    )

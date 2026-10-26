"""Gateway authentication: maps an AgentGuard API key to a tenant principal.

Keys are sent in ``X-AgentGuard-Key`` (the ``Authorization`` header usually carries the upstream
provider's credentials). Keys are never stored in plain text: static configs list SHA-256 digests.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

KEY_HEADER = "x-agentguard-key"


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    project_id: str | None = None
    key_id: str | None = None
    scopes: frozenset[str] = field(default_factory=frozenset)


class Authenticator(Protocol):
    async def authenticate(self, headers: Mapping[str, str]) -> Principal | None: ...


def _key_from(headers: Mapping[str, str]) -> str | None:
    key = headers.get(KEY_HEADER) or headers.get(KEY_HEADER.title())
    return key.strip() if key else None


class StaticKeyAuth:
    """Keys from configuration: ``{sha256(key): {"tenant_id": ..., "project_id": ...}}``."""

    def __init__(
        self,
        keys: Mapping[str, Mapping[str, Any]] | None = None,
        *,
        allow_anonymous: bool = False,
        anonymous_tenant: str = "local",
    ) -> None:
        self.keys = {k.lower(): v for k, v in (keys or {}).items()}
        self.allow_anonymous = allow_anonymous
        self.anonymous = Principal(anonymous_tenant, None, "anonymous")

    async def authenticate(self, headers: Mapping[str, str]) -> Principal | None:
        key = _key_from(headers)
        if key is None:
            return self.anonymous if self.allow_anonymous else None
        digest = hash_key(key)
        for stored, info in self.keys.items():
            if hmac.compare_digest(stored, digest):
                return Principal(
                    str(info["tenant_id"]),
                    info.get("project_id"),
                    stored[:12],
                    frozenset(info.get("scopes", ["gateway"])),
                )
        return None


class ControlPlaneAuth:
    """Validates keys against the control plane (``POST /api/v1/auth/introspect``), cached briefly."""

    def __init__(
        self, base_url: str, service_token: str, *, ttl: float = 60.0, client: httpx.AsyncClient | None = None
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.service_token = service_token
        self.ttl = ttl
        self.client = client or httpx.AsyncClient(timeout=5.0)
        self._cache: dict[str, tuple[Principal | None, float]] = {}

    async def authenticate(self, headers: Mapping[str, str]) -> Principal | None:
        key = _key_from(headers)
        if key is None:
            return None
        digest = hash_key(key)
        hit = self._cache.get(digest)
        if hit and time.monotonic() - hit[1] < self.ttl:
            return hit[0]
        try:
            r = await self.client.post(
                f"{self.base_url}/api/v1/auth/introspect",
                json={"key": key},
                headers={"authorization": f"Bearer {self.service_token}"},
            )
        except httpx.HTTPError:
            return None  # fail closed
        principal = None
        if r.status_code == 200:
            data = r.json()
            if data.get("active") and "gateway" in data.get("scopes", []):
                principal = Principal(
                    data["org_id"], data.get("project_id"), data.get("key_id"), frozenset(data["scopes"])
                )
        self._cache[digest] = (principal, time.monotonic())
        if len(self._cache) > 10_000:
            self._cache.pop(next(iter(self._cache)))
        return principal

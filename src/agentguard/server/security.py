"""Password hashing, API keys, session tokens, CSRF and signed tokens."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import string
import time
from typing import Any

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1
KEY_ALPHABET = string.ascii_letters + string.digits


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=128 * 1024 * 1024)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        # Constant-ish work even for unknown users, to avoid a timing oracle on account existence.
        hashlib.scrypt(password.encode(), salt=b"0" * 16, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=128 * 1024 * 1024)
        return False
    try:
        algo, n, r, p, salt_b64, dk_b64 = stored.split("$")
    except ValueError:
        return False
    if algo != "scrypt":
        return False
    dk = hashlib.scrypt(
        password.encode(),
        salt=base64.b64decode(salt_b64),
        n=int(n),
        r=int(r),
        p=int(p),
        maxmem=128 * 1024 * 1024,
    )
    return hmac.compare_digest(dk, base64.b64decode(dk_b64))


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def generate_api_key(live: bool = True) -> tuple[str, str, str]:
    """Return ``(key, prefix, sha256)``. Only the hash is stored; the key is shown once."""
    body = "".join(secrets.choice(KEY_ALPHABET) for _ in range(40))
    key = f"ag_{'live' if live else 'test'}_{body}"
    return key, key[:12], sha256(key)


def new_token() -> str:
    return secrets.token_urlsafe(32)


def sign(payload: dict[str, Any], secret: str, ttl_seconds: int) -> str:
    """Compact HMAC-SHA256 signed token (used for approval webhook links)."""
    body = dict(payload, exp=int(time.time()) + ttl_seconds)
    raw = (
        base64.urlsafe_b64encode(json.dumps(body, separators=(",", ":"), sort_keys=True).encode()).decode().rstrip("=")
    )
    sig = hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"


def unsign(token: str, secret: str) -> dict[str, Any] | None:
    try:
        raw, sig = token.rsplit(".", 1)
    except ValueError:
        return None
    expected = hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        body: dict[str, Any] = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except (ValueError, json.JSONDecodeError):
        return None
    if int(body.get("exp", 0)) < time.time():
        return None
    return body


def hmac_signature(secret: str, body: bytes, timestamp: str) -> str:
    """Signature for outbound webhooks: hex(HMAC_SHA256(secret, f"{timestamp}.{body}"))."""
    return hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()

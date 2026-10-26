"""Redis sliding-window rate limiter (same protocol as ``agentguard.core.ratelimit``)."""

from __future__ import annotations

import time
import uuid
from typing import Any

# Atomic: drop expired entries, count, add if under the limit.
_LUA = """
local key, now, window, limit, member = KEYS[1], tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3]), ARGV[4]
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local count = redis.call('ZCARD', key)
if count >= limit then return 0 end
redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, math.ceil(window * 1000))
return 1
"""


class RedisRateLimiter:
    def __init__(self, client: Any, prefix: str = "agentguard:rl:", *, fail_open: bool = True) -> None:
        self.client = client
        self.prefix = prefix
        self.fail_open = fail_open
        self._script = client.register_script(_LUA)

    @classmethod
    def from_url(cls, url: str, *, fail_open: bool = True) -> RedisRateLimiter:
        import redis

        return cls(redis.Redis.from_url(url, socket_timeout=0.5, socket_connect_timeout=0.5), fail_open=fail_open)

    def hit(self, key: str, limit: int, window_seconds: float) -> bool:
        try:
            return bool(
                self._script(keys=[self.prefix + key], args=[time.time(), window_seconds, limit, uuid.uuid4().hex])
            )
        except Exception:
            # Redis unavailable. API throttling fails open; policy rate limits (engine) use fail_open=False.
            return self.fail_open

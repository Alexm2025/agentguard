"""Sliding-window rate limiting. The in-memory limiter lives here; the Redis one in
``agentguard.server.ratelimit`` implements the same protocol."""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Protocol


class RateLimiter(Protocol):
    def hit(self, key: str, limit: int, window_seconds: float) -> bool:
        """Record one event for ``key``; return ``True`` if it is within the limit."""
        ...


class MemoryRateLimiter:
    def __init__(self, max_keys: int = 100_000) -> None:
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._max_keys = max_keys

    def hit(self, key: str, limit: int, window_seconds: float) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._events.get(key)
            if q is None:
                if len(self._events) >= self._max_keys:
                    # Evict the key whose newest event is oldest.
                    oldest = min(self._events, key=lambda k: self._events[k][-1] if self._events[k] else 0.0)
                    del self._events[oldest]
                q = self._events[key] = deque()
            while q and q[0] <= now - window_seconds:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

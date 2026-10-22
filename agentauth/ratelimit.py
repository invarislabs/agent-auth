"""Fixed-window request rate limiting for the registry (per client address).

`MemoryRateLimiter` counts per process. With several registry processes or
replicas, pass a Redis URL so all of them share one counter
(`RedisRateLimiter`). If Redis is unreachable, the Redis limiter lets requests
through and logs an error: rate limiting protects availability, and refusing
every request because Redis is down would cause the outage it exists to
prevent. (Replay protection and usage limits, by contrast, fail closed.)
"""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from typing import Any

log = logging.getLogger("agentauth.ratelimit")


class MemoryRateLimiter:
    def __init__(self, max_keys: int = 100_000):
        self._lock = threading.Lock()
        self._windows: OrderedDict = OrderedDict()  # least recently seen first
        self.max_keys = max_keys

    def hit(self, key: str, limit: int, period: int) -> tuple:
        """Count one request. Returns (allowed, retry_after_seconds).

        Memory is bounded by evicting the least recently seen clients, never by
        resetting everyone's counters.
        """
        now = time.time()
        window = int(now // period)
        with self._lock:
            w, n = self._windows.pop(key, (window, 0))
            if w != window:
                w, n = window, 0
            n += 1
            self._windows[key] = (w, n)
            while len(self._windows) > self.max_keys:
                self._windows.popitem(last=False)
        if n > limit:
            return False, int((window + 1) * period - now) + 1
        return True, 0


class RedisRateLimiter:
    def __init__(self, redis: Any, prefix: str = "agentauth:rl:"):
        self.r = redis
        self.prefix = prefix

    def hit(self, key: str, limit: int, period: int) -> tuple:
        now = time.time()
        window = int(now // period)
        k = f"{self.prefix}{key}:{window}"
        try:
            pipe = self.r.pipeline()
            pipe.incr(k)
            pipe.expire(k, period + 1)
            n = pipe.execute()[0]
        except Exception as e:
            log.error("rate limiter backend unavailable, allowing request: %s", e)
            return True, 0
        if int(n) > limit:
            return False, int((window + 1) * period - now) + 1
        return True, 0

"""Redis-backed replay cache and usage ledger.

Both are safe to share between any number of processes and replicas that
verify requests for the same audiences:

* `RedisNonceCache` records each (did, nonce) with ``SET NX EX`` — one atomic
  round-trip, so two replicas can never both accept the same request.
* `RedisUsageLedger` checks and charges every link of a chain inside a single
  Lua script, so the all-or-nothing guarantee of `UsageLedger.consume` holds
  across replicas too.

Failures (Redis down, timeouts, script errors) raise, and the verifiers turn
that into a 503. Nothing fails open.

Requires Redis 6.0 or newer. Use a standalone Redis, a Sentinel-managed primary, or a managed primary
endpoint. Redis Cluster is not supported: a chain's counters live under
different keys that the ledger script must touch together.

Durability: Redis keeps counters in memory. Configure AOF persistence
(``appendonly yes``) if budgets must survive a Redis restart; with no
persistence, a Redis restart resets spend, use and rate counters (and the
replay cache — which is only exposed for the ±max-skew window).
"""

from __future__ import annotations

import math
import secrets
import time
from typing import Any, Optional

from ..limits import LimitError

_redis: Any
try:
    import redis as _redis
except ImportError:  # pragma: no cover - exercised only without the extra installed
    _redis = None

DEFAULT_PREFIX = "agentauth:"
# Max grant TTL (24 h) + clock skew + margin. Used when the caller doesn't say when a grant expires.
DEFAULT_COUNTER_TTL = 24 * 3600 + 3600


def _client(url_or_client: Any):
    if isinstance(url_or_client, str):
        if _redis is None:
            raise RuntimeError('Redis support needs the redis package: pip install "agentauth[redis]"')
        return _redis.Redis.from_url(url_or_client, socket_timeout=2.0, socket_connect_timeout=2.0)
    return url_or_client


class RedisNonceCache:
    """Replay cache shared through Redis. Implements `httpsig.ReplayCache`."""

    def __init__(self, redis: Any, ttl: int = 241, prefix: str = DEFAULT_PREFIX):
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        self.r = _client(redis)
        self.ttl = int(ttl)
        self.prefix = prefix

    def check_and_store(self, did: str, nonce: str) -> bool:
        return bool(self.r.set(f"{self.prefix}nonce:{did}:{nonce}", b"1", nx=True, ex=self.ttl))

    def ping(self) -> bool:
        return bool(self.r.ping())


# KEYS: for each link i (0-based): 3i+1 spent, 3i+2 uses, 3i+3 rate zset
# ARGV: 1 n_links, 2 amount, 3 now_ms, 4 unique member,
#       then per link: total, uses, rate_count, rate_per_ms, ttl_seconds  (-1 = no limit)
_CONSUME = """
local n = tonumber(ARGV[1])
local amount = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local member = ARGV[4]
for i = 1, n do
  local a = 4 + (i - 1) * 5
  local total, uses, rc, rp = tonumber(ARGV[a + 1]), tonumber(ARGV[a + 2]), tonumber(ARGV[a + 3]), tonumber(ARGV[a + 4])
  local k = (i - 1) * 3
  if total >= 0 then
    local spent = tonumber(redis.call('GET', KEYS[k + 1]) or '0')
    if spent + amount > total then return {1, i, total - spent} end
  end
  if uses >= 0 then
    local u = tonumber(redis.call('GET', KEYS[k + 2]) or '0')
    if u + 1 > uses then return {2, i, 0} end
  end
  if rc >= 0 then
    redis.call('ZREMRANGEBYSCORE', KEYS[k + 3], '-inf', now - rp)
    if redis.call('ZCARD', KEYS[k + 3]) >= rc then
      local oldest = redis.call('ZRANGE', KEYS[k + 3], 0, 0, 'WITHSCORES')
      return {3, i, tonumber(oldest[2]) + rp - now}
    end
  end
end
for i = 1, n do
  local a = 4 + (i - 1) * 5
  local total, uses, rc, ttl = tonumber(ARGV[a + 1]), tonumber(ARGV[a + 2]), tonumber(ARGV[a + 3]), tonumber(ARGV[a + 5])
  local k = (i - 1) * 3
  if total >= 0 then redis.call('INCRBY', KEYS[k + 1], amount); redis.call('EXPIRE', KEYS[k + 1], ttl) end
  if uses >= 0 then redis.call('INCR', KEYS[k + 2]); redis.call('EXPIRE', KEYS[k + 2], ttl) end
  if rc >= 0 then redis.call('ZADD', KEYS[k + 3], now, member); redis.call('EXPIRE', KEYS[k + 3], ttl) end
end
return {0, 0, 0}
"""

# KEYS: spent keys. ARGV: amount
_REFUND = """
local amount = tonumber(ARGV[1])
for i = 1, #KEYS do
  local v = tonumber(redis.call('GET', KEYS[i]) or '0')
  if v > 0 then
    local nv = v - amount
    if nv < 0 then nv = 0 end
    redis.call('SET', KEYS[i], nv, 'KEEPTTL')
  end
end
return 1
"""


class RedisUsageLedger:
    """Usage ledger shared through Redis, with the same semantics as `limits.UsageLedger`."""

    def __init__(self, redis: Any, prefix: str = DEFAULT_PREFIX):
        self.r = _client(redis)
        self.prefix = prefix
        self._consume = self.r.register_script(_CONSUME)
        self._refund = self.r.register_script(_REFUND)

    def _keys(self, key: tuple) -> tuple:
        iss, gid = key
        base = f"{self.prefix}ledger:{iss}:{gid}"
        return f"{base}:spent", f"{base}:uses", f"{base}:rate"

    def consume(
        self, links: list, amount: int, now: Optional[float] = None, *, expires_at: Optional[dict] = None
    ) -> None:
        if not links:
            return
        now_s = time.time() if now is None else now
        keys: list = []
        argv: list = [len(links), int(amount), int(now_s * 1000), secrets.token_hex(12)]
        for key, lim in links:
            keys.extend(self._keys(key))
            exp = (expires_at or {}).get(key)
            ttl = DEFAULT_COUNTER_TTL if exp is None else max(60, math.ceil(exp - now_s) + 60)
            argv += [
                -1 if lim.total is None else lim.total,
                -1 if lim.uses is None else lim.uses,
                -1 if lim.rate_count is None else lim.rate_count,
                -1 if lim.rate_per is None else lim.rate_per * 1000,
                ttl,
            ]
        code, idx, extra = (int(x) for x in self._consume(keys=keys, args=argv))
        if code == 0:
            return
        key, lim = links[idx - 1]
        if code == 1:
            raise LimitError(f"budget exhausted ({extra} {lim.spend_unit} left under grant {key[1]})", 402)
        if code == 2:
            raise LimitError(f"grant {key[1]} has used all {lim.uses} calls", 403)
        retry = max(1, math.ceil(extra / 1000))
        raise LimitError(f"rate limit {lim.rate_count}/{lim.rate_per}s reached; retry in {retry}s", 429)

    def refund(self, links: list, amount: int) -> None:
        keys = [self._keys(key)[0] for key, lim in links if lim.total is not None]
        if keys and amount:
            self._refund(keys=keys, args=[int(amount)])

    def usage(self, key: tuple) -> dict:
        spent, uses, _ = self._keys(key)
        s, u = self.r.mget([spent, uses])
        return {"spent": int(s or 0), "uses": int(u or 0)}

    def prune(self, now: Optional[float] = None) -> int:
        """Redis expires counters on its own (each key's TTL follows its grant's expiry)."""
        return 0

    def ping(self) -> bool:
        return bool(self.r.ping())

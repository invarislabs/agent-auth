"""Registry configuration, read from the environment and validated at startup.

Every setting has an ``AGENTAUTH_*`` environment variable. Invalid values stop
the process with a clear message instead of starting with a surprising default.
See docs/operations.md for the full table.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Optional


class ConfigError(ValueError):
    pass


_RATE_RE = re.compile(r"\A(\d+)/(\d+)s?\Z")


def parse_rate(value: str, name: str) -> Optional[tuple]:
    """'60/60' -> (60, 60) meaning 60 requests per 60 s. '0' or 'off' disables."""
    v = value.strip().lower()
    if v in ("0", "off", "none", "disabled", ""):
        return None
    m = _RATE_RE.match(v)
    if not m or int(m.group(1)) <= 0 or int(m.group(2)) <= 0:
        raise ConfigError(f"{name} must look like COUNT/SECONDS (e.g. 60/60) or 'off', got {value!r}")
    return int(m.group(1)), int(m.group(2))


def _bool(value: str, name: str) -> bool:
    v = value.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name} must be true or false, got {value!r}")


def _int(value: str, name: str, lo: int, hi: int) -> int:
    try:
        n = int(value)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {value!r}") from None
    if not lo <= n <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}, got {n}")
    return n


def _secret(env: Mapping[str, str], name: str) -> Optional[str]:
    """Read NAME, or the contents of the file named by NAME_FILE (for Docker/K8s secrets)."""
    path = env.get(name + "_FILE")
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                value = f.read().strip()
        except OSError as e:
            raise ConfigError(f"{name}_FILE: cannot read {path}: {e}") from None
    else:
        value = (env.get(name) or "").strip()
    if value and len(value) < 16:
        raise ConfigError(f"{name} must be at least 16 characters")
    return value or None


@dataclass
class Settings:
    database_url: str = "agentauth.db"
    audiences: set = field(default_factory=lambda: {"localhost:8000", "127.0.0.1:8000"})
    auto_migrate: bool = True
    redis_url: Optional[str] = None
    max_body_bytes: int = 16 * 1024
    max_skew: int = 120
    resolve_cache_seconds: int = 30
    rate_limit_writes: Optional[tuple] = (60, 60)
    rate_limit_reads: Optional[tuple] = (1200, 60)
    trusted_proxy_hops: int = 0
    registration_token: Optional[str] = None
    metrics_enabled: bool = True
    log_level: str = "INFO"
    log_format: str = "json"

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> Settings:
        env = os.environ if env is None else env
        s = cls()
        if env.get("AGENTAUTH_DATABASE_URL"):
            s.database_url = env["AGENTAUTH_DATABASE_URL"]
        elif env.get("AGENTAUTH_DB"):  # v0.3 name: a SQLite path
            s.database_url = env["AGENTAUTH_DB"]
        if "AGENTAUTH_AUDIENCES" in env:
            s.audiences = {a.strip().lower() for a in env["AGENTAUTH_AUDIENCES"].split(",") if a.strip()}
        if "AGENTAUTH_AUTO_MIGRATE" in env:
            s.auto_migrate = _bool(env["AGENTAUTH_AUTO_MIGRATE"], "AGENTAUTH_AUTO_MIGRATE")
        s.redis_url = env.get("AGENTAUTH_REDIS_URL") or None
        if "AGENTAUTH_MAX_BODY_BYTES" in env:
            s.max_body_bytes = _int(env["AGENTAUTH_MAX_BODY_BYTES"], "AGENTAUTH_MAX_BODY_BYTES", 1024, 1 << 20)
        if "AGENTAUTH_MAX_SKEW" in env:
            s.max_skew = _int(env["AGENTAUTH_MAX_SKEW"], "AGENTAUTH_MAX_SKEW", 5, 600)
        if "AGENTAUTH_RESOLVE_CACHE_SECONDS" in env:
            s.resolve_cache_seconds = _int(env["AGENTAUTH_RESOLVE_CACHE_SECONDS"], "AGENTAUTH_RESOLVE_CACHE_SECONDS", 0, 3600)
        if "AGENTAUTH_RATE_LIMIT_WRITES" in env:
            s.rate_limit_writes = parse_rate(env["AGENTAUTH_RATE_LIMIT_WRITES"], "AGENTAUTH_RATE_LIMIT_WRITES")
        if "AGENTAUTH_RATE_LIMIT_READS" in env:
            s.rate_limit_reads = parse_rate(env["AGENTAUTH_RATE_LIMIT_READS"], "AGENTAUTH_RATE_LIMIT_READS")
        if "AGENTAUTH_TRUSTED_PROXY_HOPS" in env:
            s.trusted_proxy_hops = _int(env["AGENTAUTH_TRUSTED_PROXY_HOPS"], "AGENTAUTH_TRUSTED_PROXY_HOPS", 0, 10)
        s.registration_token = _secret(env, "AGENTAUTH_REGISTRATION_TOKEN")
        if "AGENTAUTH_METRICS" in env:
            s.metrics_enabled = _bool(env["AGENTAUTH_METRICS"], "AGENTAUTH_METRICS")
        if "AGENTAUTH_LOG_LEVEL" in env:
            s.log_level = env["AGENTAUTH_LOG_LEVEL"].upper()
        if "AGENTAUTH_LOG_FORMAT" in env:
            s.log_format = env["AGENTAUTH_LOG_FORMAT"].lower()
        s.validate()
        return s

    def validate(self) -> None:
        if not self.audiences:
            raise ConfigError("AGENTAUTH_AUDIENCES must list at least one host[:port]")
        for a in self.audiences:
            if any(c.isspace() for c in a) or "/" in a or not a:
                raise ConfigError(f"audience {a!r} must be a bare host[:port], not a URL")
        if self.log_level not in ("DEBUG", "INFO", "WARNING", "ERROR"):
            raise ConfigError("AGENTAUTH_LOG_LEVEL must be DEBUG, INFO, WARNING or ERROR")
        if self.log_format not in ("json", "text"):
            raise ConfigError("AGENTAUTH_LOG_FORMAT must be json or text")
        if self.redis_url and not self.redis_url.startswith(("redis://", "rediss://", "unix://")):
            raise ConfigError("AGENTAUTH_REDIS_URL must be a redis://, rediss:// or unix:// URL")

    def describe(self) -> dict:
        """Settings safe to log (no secrets, no credentials in URLs; nothing derived from the
        registration token — /v1/info reports the registration mode)."""
        return {
            "database": _redact(self.database_url),
            "audiences": sorted(self.audiences),
            "auto_migrate": self.auto_migrate,
            "redis": _redact(self.redis_url) if self.redis_url else None,
            "max_body_bytes": self.max_body_bytes,
            "max_skew": self.max_skew,
            "rate_limit_writes": self.rate_limit_writes,
            "rate_limit_reads": self.rate_limit_reads,
            "trusted_proxy_hops": self.trusted_proxy_hops,
            "metrics": self.metrics_enabled,
        }


def _redact(url: Optional[str]) -> Optional[str]:
    if not url:
        return url
    return re.sub(r"//([^:/@]+):([^@]+)@", r"//\1:***@", url)

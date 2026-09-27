"""Resource, spend, rate and use limits on capability grants.

A grant may carry an optional ``limits`` object:

    {
      "resources": ["/reports/*", "repo:acme/website"],  # what it may touch
      "spend":     {"unit": "USD-cents", "per_call": 5000, "total": 20000},
      "rate":      {"count": 10, "per": 60},             # ≤ 10 calls per 60 s
      "uses":      100                                   # ≤ 100 calls in total
    }

Every field is optional, and a missing field means "no limit from this link".
Limits only ever tighten down a delegation chain. A service enforces **every
link's** limits, so a child can never escape its parent. That includes the
stateful ones: a parent's budget, rate and use counters are shared by all the
grants delegated beneath it.

Resources are opaque strings: file paths, repo names, account ids. A pattern
is either exact, or ends in ``*`` to match by prefix.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional

MAX_RESOURCES = 32
MAX_RESOURCE_LEN = 256


class LimitError(Exception):
    def __init__(self, message: str, status: int = 403):
        super().__init__(message)
        self.status = status


# --------------------------------------------------------------------------- #
# Resource patterns
# --------------------------------------------------------------------------- #


def _valid_pattern(p: str) -> bool:
    return (
        isinstance(p, str)
        and 0 < len(p) <= MAX_RESOURCE_LEN
        and "*" not in p[:-1]
        and not any(c.isspace() or ord(c) < 32 for c in p)
    )


def _unsafe_resource(r: str) -> bool:
    """Reject path traversal and wildcards in *requested* resources."""
    return (
        not isinstance(r, str)
        or not r
        or "*" in r
        or any(ord(c) < 32 for c in r)
        or any(seg in ("..", ".") for seg in r.replace("\\", "/").split("/"))
    )


def pattern_matches(pattern: str, resource: str) -> bool:
    if pattern.endswith("*"):
        return resource.startswith(pattern[:-1])
    return resource == pattern


def pattern_covers(parent: str, child: str) -> bool:
    """Does every resource matched by `child` also match `parent`?"""
    if parent.endswith("*"):
        return child.startswith(parent[:-1])
    return child == parent


# --------------------------------------------------------------------------- #
# Limits
# --------------------------------------------------------------------------- #


def _pos_int(v, name: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
        raise LimitError(f"{name} must be a positive integer", 400)
    return v


@dataclass(frozen=True)
class Limits:
    resources: Optional[tuple] = None
    spend_unit: Optional[str] = None
    per_call: Optional[int] = None
    total: Optional[int] = None
    rate_count: Optional[int] = None
    rate_per: Optional[int] = None
    uses: Optional[int] = None

    # -- (de)serialisation -------------------------------------------------- #

    @classmethod
    def build(
        cls,
        *,
        resources=None,
        spend_unit=None,
        per_call=None,
        total=None,
        rate=None,  # (count, per_seconds)
        uses=None,
    ) -> "Limits":
        d: dict = {}
        if resources is not None:
            d["resources"] = list(resources)
        if per_call is not None or total is not None:
            d["spend"] = {"unit": spend_unit or "USD-cents"}
            if per_call is not None:
                d["spend"]["per_call"] = per_call
            if total is not None:
                d["spend"]["total"] = total
        if rate is not None:
            d["rate"] = {"count": rate[0], "per": rate[1]}
        if uses is not None:
            d["uses"] = uses
        return cls.from_dict(d)

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> "Limits":
        if d is None:
            return cls()
        if not isinstance(d, dict):
            raise LimitError("limits must be an object", 400)
        unknown = set(d) - {"resources", "spend", "rate", "uses"}
        if unknown:
            # Fail closed: a limit we don't understand must not be silently ignored.
            raise LimitError(f"unknown limit(s): {', '.join(sorted(unknown))}", 400)
        kw: dict = {}
        if "resources" in d:
            rs = d["resources"]
            if not isinstance(rs, list) or not rs or len(rs) > MAX_RESOURCES or not all(map(_valid_pattern, rs)):
                raise LimitError("resources must be 1–32 patterns (exact, or ending in *)", 400)
            kw["resources"] = tuple(sorted(set(rs)))
        if "spend" in d:
            sp = d["spend"]
            if not isinstance(sp, dict) or set(sp) - {"unit", "per_call", "total"}:
                raise LimitError("spend must be {unit, per_call?, total?}", 400)
            if not isinstance(sp.get("unit"), str) or not sp["unit"]:
                raise LimitError("spend.unit is required", 400)
            if "per_call" not in sp and "total" not in sp:
                raise LimitError("spend needs per_call and/or total", 400)
            kw["spend_unit"] = sp["unit"]
            if "per_call" in sp:
                kw["per_call"] = _pos_int(sp["per_call"], "spend.per_call")
            if "total" in sp:
                kw["total"] = _pos_int(sp["total"], "spend.total")
        if "rate" in d:
            rt = d["rate"]
            if not isinstance(rt, dict) or set(rt) != {"count", "per"}:
                raise LimitError("rate must be {count, per}", 400)
            kw["rate_count"] = _pos_int(rt["count"], "rate.count")
            kw["rate_per"] = _pos_int(rt["per"], "rate.per")
            if kw["rate_per"] > 86400:
                raise LimitError("rate.per may be at most 86400 seconds", 400)
        if "uses" in d:
            kw["uses"] = _pos_int(d["uses"], "uses")
        return cls(**kw)

    def to_dict(self) -> Optional[dict]:
        d: dict = {}
        if self.resources is not None:
            d["resources"] = list(self.resources)
        if self.spend_unit is not None:
            d["spend"] = {"unit": self.spend_unit}
            if self.per_call is not None:
                d["spend"]["per_call"] = self.per_call
            if self.total is not None:
                d["spend"]["total"] = self.total
        if self.rate_count is not None:
            d["rate"] = {"count": self.rate_count, "per": self.rate_per}
        if self.uses is not None:
            d["uses"] = self.uses
        return d or None

    @property
    def empty(self) -> bool:
        return self.to_dict() is None

    @property
    def stateful(self) -> bool:
        return self.total is not None or self.rate_count is not None or self.uses is not None

    # -- attenuation -------------------------------------------------------- #

    def narrowing_violation(self, child: "Limits") -> Optional[str]:
        """Return why `child` would loosen these limits, or None if it only tightens them."""
        if self.resources is not None:
            if child.resources is None:
                return "child drops the parent's resource restriction"
            for c in child.resources:
                if not any(pattern_covers(p, c) for p in self.resources):
                    return f"resource {c!r} is outside the parent's"
        if self.spend_unit is not None:
            if child.spend_unit is not None and child.spend_unit != self.spend_unit:
                return "spend unit differs from the parent's"
            if self.per_call is not None and (child.per_call is None or child.per_call > self.per_call):
                return "per-call spend exceeds the parent's"
            if self.total is not None and (child.total is None or child.total > self.total):
                return "spend total exceeds the parent's"
        if self.rate_count is not None:
            if child.rate_count is None:
                return "child drops the parent's rate limit"
            # child.count / child.per <= parent.count / parent.per
            if child.rate_count * self.rate_per > self.rate_count * child.rate_per:
                return "rate exceeds the parent's"
        if self.uses is not None and (child.uses is None or child.uses > self.uses):
            return "use count exceeds the parent's"
        return None

    def inherit_into(self, child: "Limits") -> "Limits":
        """Fill in any limit the child leaves unset with the parent's value.

        Used at issue time so a delegated grant is self-describing. The
        service enforces every link anyway.
        """
        return Limits(
            resources=child.resources if child.resources is not None else self.resources,
            spend_unit=child.spend_unit or self.spend_unit,
            per_call=child.per_call if child.per_call is not None else self.per_call,
            total=child.total if child.total is not None else self.total,
            rate_count=child.rate_count if child.rate_count is not None else self.rate_count,
            rate_per=child.rate_per if child.rate_count is not None else self.rate_per,
            uses=child.uses if child.uses is not None else self.uses,
        )

    # -- stateless per-call checks ------------------------------------------ #

    def check_call(self, *, resource: Optional[str], amount: int, unit: Optional[str]) -> None:
        if self.resources is not None:
            if resource is None:
                raise LimitError("grant is limited to specific resources, but this endpoint names none")
            if _unsafe_resource(resource):
                raise LimitError("requested resource is not a plain name (no '..', '.', '*')", 400)
            if not any(pattern_matches(p, resource) for p in self.resources):
                raise LimitError(f"grant does not cover resource {resource!r}")
        if self.spend_unit is not None and amount:
            if unit != self.spend_unit:
                raise LimitError(f"grant spends in {self.spend_unit}, endpoint charges in {unit}")
            if self.per_call is not None and amount > self.per_call:
                raise LimitError(f"amount {amount} exceeds per-call limit {self.per_call}")
            if self.total is not None and amount > self.total:
                raise LimitError(f"amount {amount} exceeds total budget {self.total}")


# --------------------------------------------------------------------------- #
# Usage ledger (stateful limits)
# --------------------------------------------------------------------------- #


class UsageLedger:
    """Tracks spend, rate and use counters per (issuer, grant id).

    In-memory and single-process. For more than one replica, implement the
    same `consume` / `refund` / `usage` interface on Redis or your database
    (a Lua script or a transaction gives the same all-or-nothing behaviour).
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._spent: dict = {}
        self._uses: dict = {}
        self._calls: dict = {}  # key -> deque of timestamps

    def consume(self, links: list, amount: int, now: Optional[float] = None) -> None:
        """Atomically charge one call (and `amount`) against every limited link, or none of them.

        `links` is a list of ((issuer, grant_id), Limits).
        """
        now = time.time() if now is None else now
        with self._lock:
            for key, lim in links:
                if lim.total is not None and self._spent.get(key, 0) + amount > lim.total:
                    left = lim.total - self._spent.get(key, 0)
                    raise LimitError(f"budget exhausted ({left} {lim.spend_unit} left under grant {key[1]})", 402)
                if lim.uses is not None and self._uses.get(key, 0) + 1 > lim.uses:
                    raise LimitError(f"grant {key[1]} has used all {lim.uses} calls", 403)
                if lim.rate_count is not None:
                    q = self._calls.get(key)
                    if q is not None:
                        while q and q[0] <= now - lim.rate_per:
                            q.popleft()
                        if len(q) >= lim.rate_count:
                            retry = int(q[0] + lim.rate_per - now) + 1
                            raise LimitError(f"rate limit {lim.rate_count}/{lim.rate_per}s reached; retry in {retry}s", 429)
            for key, lim in links:
                if lim.total is not None:
                    self._spent[key] = self._spent.get(key, 0) + amount
                if lim.uses is not None:
                    self._uses[key] = self._uses.get(key, 0) + 1
                if lim.rate_count is not None:
                    self._calls.setdefault(key, deque()).append(now)

    def refund(self, links: list, amount: int) -> None:
        """Give back spend (e.g. the downstream purchase failed). Uses and rate are not refunded."""
        with self._lock:
            for key, lim in links:
                if lim.total is not None:
                    self._spent[key] = max(0, self._spent.get(key, 0) - amount)

    def usage(self, key: tuple) -> dict:
        with self._lock:
            return {"spent": self._spent.get(key, 0), "uses": self._uses.get(key, 0)}

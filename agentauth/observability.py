"""Structured logging and a dependency-free Prometheus metrics registry."""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from collections.abc import Iterable
from typing import Optional

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

_STD_ATTRS = set(vars(logging.LogRecord("x", 0, "", 0, "", (), None))) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """One JSON object per line. Extra fields passed via `extra=` are included."""

    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for k, v in vars(record).items():
            if k not in _STD_ATTRS and not k.startswith("_"):
                out[k] = v
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, default=str)


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if fmt == "json" else logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger("agentauth")
    root.handlers[:] = [handler]
    root.setLevel(level)
    root.propagate = False


# --------------------------------------------------------------------------- #
# Metrics (Prometheus text exposition format 0.0.4)
# --------------------------------------------------------------------------- #


def _labels(names: tuple, values: tuple) -> str:
    if not names:
        return ""
    esc = (str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") for v in values)
    return "{" + ",".join(f'{n}="{v}"' for n, v in zip(names, esc, strict=True)) + "}"


class Counter:
    def __init__(self, name: str, help: str, labels: tuple = ()):
        self.name, self.help, self.labelnames = name, help, labels
        self._v: dict = {}
        self._lock = threading.Lock()

    def inc(self, *labels, amount: float = 1) -> None:
        with self._lock:
            self._v[labels] = self._v.get(labels, 0) + amount

    def value(self, *labels) -> float:
        with self._lock:
            return self._v.get(labels, 0)

    def render(self) -> Iterable[str]:
        yield f"# HELP {self.name} {self.help}"
        yield f"# TYPE {self.name} counter"
        with self._lock:
            for k, v in sorted(self._v.items()):
                yield f"{self.name}{_labels(self.labelnames, k)} {v}"


class Gauge:
    def __init__(self, name: str, help: str, fn):
        self.name, self.help, self.fn = name, help, fn

    def render(self) -> Iterable[str]:
        yield f"# HELP {self.name} {self.help}"
        yield f"# TYPE {self.name} gauge"
        try:
            yield f"{self.name} {float(self.fn())}"
        except Exception:  # a failing gauge must never break /metrics
            return


class Histogram:
    BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

    def __init__(self, name: str, help: str, labels: tuple = (), buckets: Optional[tuple] = None):
        self.name, self.help, self.labelnames = name, help, labels
        self.buckets = buckets or self.BUCKETS
        self._v: dict = {}
        self._lock = threading.Lock()

    def observe(self, value: float, *labels) -> None:
        with self._lock:
            counts, total = self._v.get(labels, ([0] * len(self.buckets), [0, 0.0]))
            for i, b in enumerate(self.buckets):
                if value <= b:
                    counts[i] += 1
            total[0] += 1
            total[1] += value
            self._v[labels] = (counts, total)

    def render(self) -> Iterable[str]:
        yield f"# HELP {self.name} {self.help}"
        yield f"# TYPE {self.name} histogram"
        with self._lock:
            for k, (counts, (n, s)) in sorted(self._v.items()):
                for b, c in zip(self.buckets, counts, strict=True):
                    yield f"{self.name}_bucket{_labels(self.labelnames + ('le',), k + (repr(b),))} {c}"
                yield f"{self.name}_bucket{_labels(self.labelnames + ('le',), k + ('+Inf',))} {n}"
                yield f"{self.name}_count{_labels(self.labelnames, k)} {n}"
                yield f"{self.name}_sum{_labels(self.labelnames, k)} {s}"


class Registry:
    def __init__(self):
        self.metrics: list = []

    def add(self, m):
        self.metrics.append(m)
        return m

    def render(self) -> str:
        lines = []
        for m in self.metrics:
            lines.extend(m.render())
        return "\n".join(lines) + "\n"

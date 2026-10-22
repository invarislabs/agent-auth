"""Tamper-evident audit log of authorization decisions, for relying services.

Each entry records who acted (the agent), on whose authority (principal and
the full delegation path), under which grants, what was asked (scopes,
resource, amount) and what the service decided. Entries are hash-chained:

    entry_n.prev = digest(canonical_json(entry_{n-1}))

and, if the log has a signing key, each entry is signed with it. `verify()`
replays the chain and checks every signature.

What that buys you:

* Without a signing key, the chain shows that entries weren't edited,
  reordered or removed *in the middle*, provided you keep a copy of a recent
  head digest somewhere the database's attacker can't reach (export `head()`
  to your log pipeline). Someone with write access could otherwise rewrite
  the whole chain.
* With a signing key held outside the database, rewriting history also
  requires that key.

Truncating the newest entries is only detectable against an exported head.

Storage is SQLite. Writes take an immediate transaction, so several worker
processes on one host can share a file. Replicas on different hosts should
each keep their own log (set `instance`) and export heads centrally.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from .crypto import Signer, canonical_json, digest, verify

VERSION = "agentauth-audit/1"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    seq     INTEGER PRIMARY KEY,
    digest  TEXT NOT NULL,
    entry   TEXT NOT NULL
)
"""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class AuditLog:
    def __init__(self, path: str = ":memory:", *, signer: Optional[Signer] = None, instance: str = ""):
        self.path, self.signer, self.instance = path, signer, instance
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10.0)
        self._db.execute("PRAGMA busy_timeout=10000")
        if path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute(_SCHEMA)

    def record(
        self,
        *,
        agent: Optional[str],
        outcome: str,
        status: int,
        scopes: Optional[list] = None,
        authz: Any = None,
        resource: Optional[str] = None,
        amount: int = 0,
        unit: Optional[str] = None,
        reason: Optional[str] = None,
        request_id: Optional[str] = None,
        method: Optional[str] = None,
        path: Optional[str] = None,
    ) -> dict:
        """Append one decision. `authz` is the `AuthorizedAgent`, when the grant chain verified."""
        if outcome not in ("allowed", "denied"):
            raise ValueError("outcome must be 'allowed' or 'denied'")
        body: dict = {
            "v": VERSION,
            "ts": _now(),
            "instance": self.instance,
            "agent": agent,
            "principal": getattr(authz, "principal", None),
            "via": list(getattr(authz, "via", []) or []),
            "grants": [[g.iss, g.id] for g in authz.chain.links] if authz is not None else [],
            "scopes": list(scopes or []),
            "resource": resource,
            "amount": int(amount or 0),
            "unit": unit,
            "charged": int(getattr(authz, "charged", 0) or 0),
            "outcome": outcome,
            "status": int(status),
            "reason": (reason or None) and str(reason)[:500],
            "request_id": request_id,
            "method": method,
            "path": (path or None) and path[:2048],
        }
        with self._lock:
            cur = self._db.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                row = cur.execute("SELECT seq, digest FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
                body["seq"] = (row[0] + 1) if row else 0
                body["prev"] = row[1] if row else None
                msg = canonical_json(body)
                entry: dict = {"body": body}
                if self.signer is not None:
                    entry["key"] = self.signer.public_multikey
                    entry["sig"] = self.signer.sign(msg)
                cur.execute("INSERT INTO audit_log(seq, digest, entry) VALUES (?,?,?)",
                            (body["seq"], digest(msg), json.dumps(entry)))
                cur.execute("COMMIT")
            except BaseException:
                cur.execute("ROLLBACK")
                raise
        return entry

    def head(self) -> Optional[tuple]:
        """(seq, digest) of the newest entry — export this somewhere safe."""
        with self._lock:
            row = self._db.execute("SELECT seq, digest FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        return (row[0], row[1]) if row else None

    def entries(self, after: int = -1, limit: int = 1000) -> list:
        with self._lock:
            rows = self._db.execute(
                "SELECT entry FROM audit_log WHERE seq>? ORDER BY seq LIMIT ?", (after, limit)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def verify(self, *, public_key: Optional[str] = None, expected_head: Optional[tuple] = None) -> list:
        """Replay the chain. Returns a list of problems; empty means it verified.

        `public_key`: require every entry to be signed by this key.
        `expected_head`: an exported (seq, digest) that must still be in the chain.
        """
        problems: list = []
        prev: Optional[str] = None
        expect = 0
        head_seen = expected_head is None
        after = -1
        while True:
            with self._lock:
                rows = self._db.execute(
                    "SELECT seq, digest, entry FROM audit_log WHERE seq>? ORDER BY seq LIMIT 1000", (after,)).fetchall()
            if not rows:
                break
            for seq, stored_digest, raw in rows:
                after = seq
                entry = json.loads(raw)
                body = entry.get("body", {})
                if seq != expect or body.get("seq") != seq:
                    problems.append(f"entry {seq}: sequence gap or reorder (expected {expect})")
                expect = seq + 1
                if body.get("prev") != prev:
                    problems.append(f"entry {seq}: does not chain to the previous entry")
                msg = canonical_json(body)
                d = digest(msg)
                if d != stored_digest:
                    problems.append(f"entry {seq}: stored digest does not match its contents")
                if public_key is not None:
                    if entry.get("key") != public_key or not verify(public_key, msg, entry.get("sig", "")):
                        problems.append(f"entry {seq}: missing or bad signature")
                elif "sig" in entry and not verify(entry.get("key", ""), msg, entry["sig"]):
                    problems.append(f"entry {seq}: bad signature")
                if expected_head is not None and (seq, d) == tuple(expected_head):
                    head_seen = True
                prev = d
        if not head_seen and expected_head is not None:
            problems.append(f"exported head {tuple(expected_head)} is not in the log (truncated or rewritten)")
        return problems

    def close(self) -> None:
        with self._lock:
            self._db.close()

"""SQLite persistence for key event logs and derived identity state."""

from __future__ import annotations

import dataclasses
import json
import sqlite3
import threading
from typing import Optional

from .identity import IdentityState, event_digest

_SCHEMA = """
CREATE TABLE IF NOT EXISTS identities (
    did         TEXT PRIMARY KEY,
    controller  TEXT,
    active      INTEGER NOT NULL,
    state       TEXT NOT NULL,
    updated     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS identities_controller ON identities(controller);
CREATE TABLE IF NOT EXISTS events (
    did     TEXT NOT NULL,
    seq     INTEGER NOT NULL,
    digest  TEXT NOT NULL,
    event   TEXT NOT NULL,
    PRIMARY KEY (did, seq)
);
CREATE TABLE IF NOT EXISTS revocations (
    issuer      TEXT NOT NULL,
    grant_id    TEXT NOT NULL,
    revoked_at  INTEGER NOT NULL,
    event       TEXT NOT NULL,
    PRIMARY KEY (issuer, grant_id)
);
"""


class Conflict(Exception):
    pass


class Store:
    def __init__(self, path: str = ":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)
        self._lock = threading.Lock()

    # -- reads ------------------------------------------------------------- #

    def get_state(self, did: str) -> Optional[IdentityState]:
        row = self._db.execute("SELECT state FROM identities WHERE did=?", (did,)).fetchone()
        if not row:
            return None
        data = json.loads(row[0])
        data["history"] = [tuple(h) for h in data["history"]]
        return IdentityState(**data)

    def get_log(self, did: str) -> list:
        rows = self._db.execute("SELECT event FROM events WHERE did=? ORDER BY seq", (did,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def list_by_controller(self, controller: str) -> list:
        rows = self._db.execute(
            "SELECT did, active FROM identities WHERE controller=? ORDER BY did", (controller,)
        ).fetchall()
        return [{"did": d, "active": bool(a)} for d, a in rows]

    # -- writes ------------------------------------------------------------ #

    def append(self, event: dict, new_state: IdentityState, expected_prev_seq: Optional[int]) -> None:
        """Atomically append `event` and persist `new_state`.

        `expected_prev_seq` is None for inception. Concurrent writers racing on
        the same seq are rejected with Conflict (optimistic concurrency).
        """
        body = event["body"]
        state_json = json.dumps(dataclasses.asdict(new_state))
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                cur = self._db.execute("SELECT MAX(seq) FROM events WHERE did=?", (body["did"],)).fetchone()[0]
                if cur != expected_prev_seq:
                    raise Conflict("identity changed concurrently or already exists")
                self._db.execute(
                    "INSERT INTO events(did, seq, digest, event) VALUES (?,?,?,?)",
                    (body["did"], body["seq"], event_digest(event), json.dumps(event)),
                )
                self._db.execute(
                    "INSERT INTO identities(did, controller, active, state, updated) VALUES (?,?,?,?,?) "
                    "ON CONFLICT(did) DO UPDATE SET active=excluded.active, state=excluded.state, updated=excluded.updated",
                    (new_state.did, new_state.controller, int(new_state.active), state_json, new_state.updated),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    # -- grant revocations ------------------------------------------------- #

    def add_revocation(self, issuer: str, grant_id: str, revoked_at: int, event: dict) -> bool:
        """Returns False if it was already revoked."""
        with self._lock:
            cur = self._db.execute(
                "INSERT OR IGNORE INTO revocations(issuer, grant_id, revoked_at, event) VALUES (?,?,?,?)",
                (issuer, grant_id, revoked_at, json.dumps(event)),
            )
            return cur.rowcount == 1

    def revoked_among(self, pairs: list) -> list:
        out = []
        for iss, gid in pairs:
            row = self._db.execute(
                "SELECT 1 FROM revocations WHERE issuer=? AND grant_id=?", (iss, gid)
            ).fetchone()
            if row:
                out.append([iss, gid])
        return out

"""Registry persistence: key event logs, derived identity state and grant revocations.

Two backends share one interface:

* `Store` / `SQLiteStore` — a single file (or ``:memory:``). One registry
  host; several worker processes on that host are fine.
* `PostgresStore` — for running several registry replicas. Needs
  ``pip install "agentauth[postgres]"``.

`open_store(url)` picks one from a URL (``sqlite:///path``, a bare path, or
``postgresql://…``).

The schema is versioned (table ``schema_migrations``). `migrate()` brings a
database up to date and is idempotent; a database *newer* than this code is
refused, so an old binary can never write to a schema it doesn't understand.
"""

from __future__ import annotations

import dataclasses
import json
import sqlite3
import threading
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any, Optional

from .identity import IdentityState, InvalidEvent, event_digest, verify_log


class Conflict(Exception):
    pass


class SchemaError(RuntimeError):
    """The database schema is missing migrations, or is newer than this code."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _state_from_json(raw: str) -> IdentityState:
    data = json.loads(raw)
    data["history"] = [tuple(h) for h in data["history"]]
    return IdentityState(**data)


# Each migration is (version, description, [statements]). Statements must be
# idempotent for version 1, because databases created by v0.3 already have
# those tables but no migrations table.
_SQLITE_MIGRATIONS = [
    (1, "baseline: identities, events, revocations", [
        """CREATE TABLE IF NOT EXISTS identities (
            did         TEXT PRIMARY KEY,
            controller  TEXT,
            active      INTEGER NOT NULL,
            state       TEXT NOT NULL,
            updated     TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS identities_controller ON identities(controller)",
        """CREATE TABLE IF NOT EXISTS events (
            did     TEXT NOT NULL,
            seq     INTEGER NOT NULL,
            digest  TEXT NOT NULL,
            event   TEXT NOT NULL,
            PRIMARY KEY (did, seq)
        )""",
        """CREATE TABLE IF NOT EXISTS revocations (
            issuer      TEXT NOT NULL,
            grant_id    TEXT NOT NULL,
            revoked_at  INTEGER NOT NULL,
            event       TEXT NOT NULL,
            PRIMARY KEY (issuer, grant_id)
        )""",
    ]),
    (2, "record when the registry accepted each event and revocation", [
        "ALTER TABLE events ADD COLUMN received_at TEXT",
        "ALTER TABLE revocations ADD COLUMN received_at TEXT",
    ]),
]

_PG_MIGRATIONS = [
    (1, "baseline: identities, events, revocations", [
        """CREATE TABLE IF NOT EXISTS identities (
            did         TEXT PRIMARY KEY,
            controller  TEXT,
            active      BOOLEAN NOT NULL,
            state       TEXT NOT NULL,
            updated     TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS identities_controller ON identities(controller)",
        """CREATE TABLE IF NOT EXISTS events (
            did     TEXT NOT NULL,
            seq     INTEGER NOT NULL,
            digest  TEXT NOT NULL,
            event   TEXT NOT NULL,
            PRIMARY KEY (did, seq)
        )""",
        """CREATE TABLE IF NOT EXISTS revocations (
            issuer      TEXT NOT NULL,
            grant_id    TEXT NOT NULL,
            revoked_at  BIGINT NOT NULL,
            event       TEXT NOT NULL,
            PRIMARY KEY (issuer, grant_id)
        )""",
    ]),
    (2, "record when the registry accepted each event and revocation", [
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS received_at TEXT",
        "ALTER TABLE revocations ADD COLUMN IF NOT EXISTS received_at TEXT",
    ]),
]

SCHEMA_VERSION = _SQLITE_MIGRATIONS[-1][0]
assert SCHEMA_VERSION == _PG_MIGRATIONS[-1][0]  # nosec B101

MAX_PAGE = 1000


class _BaseStore:
    """Behaviour shared by both backends; subclasses provide `_q` and `_tx`."""

    migrations: list = []
    placeholder = "?"

    # -- plumbing (implemented by subclasses) ------------------------------ #

    def _q(self, sql: str, args: tuple = ()) -> list:  # pragma: no cover - abstract
        raise NotImplementedError

    def _tx(self):  # pragma: no cover - abstract
        raise NotImplementedError

    def _sql(self, sql: str) -> str:
        return sql if self.placeholder == "?" else sql.replace("?", self.placeholder)

    # -- schema ------------------------------------------------------------ #

    def schema_version(self) -> int:
        try:
            rows = self._q("SELECT MAX(version) FROM schema_migrations")
        except Exception:
            return 0
        return int(rows[0][0] or 0)

    def pending_migrations(self) -> list:
        current = self.schema_version()
        return [(v, d) for v, d, _ in self.migrations if v > current]

    def check_schema(self) -> None:
        current = self.schema_version()
        if current > SCHEMA_VERSION:
            raise SchemaError(
                f"database schema is version {current}, newer than this AgentAuth ({SCHEMA_VERSION}); upgrade AgentAuth"
            )
        if current < SCHEMA_VERSION:
            raise SchemaError(
                f"database schema is version {current}, expected {SCHEMA_VERSION}; run `agentauth db migrate`"
            )

    def migrate(self) -> list:
        """Apply pending migrations. Returns the versions applied."""
        applied = []
        with self._tx() as cur:
            cur.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "version INTEGER PRIMARY KEY, description TEXT NOT NULL, applied_at TEXT NOT NULL)"
            )
        if self.schema_version() > SCHEMA_VERSION:
            raise SchemaError(f"database schema {self.schema_version()} is newer than this AgentAuth ({SCHEMA_VERSION})")
        for version, desc, statements in self.migrations:
            with self._tx() as cur:
                # Re-read inside the write transaction: another process may have applied it meanwhile.
                cur.execute("SELECT MAX(version) FROM schema_migrations")
                if int(cur.fetchone()[0] or 0) >= version:
                    continue
                for stmt in statements:
                    self._exec_migration(cur, stmt)
                cur.execute(
                    self._sql("INSERT INTO schema_migrations(version, description, applied_at) VALUES (?,?,?)"),
                    (version, desc, _now()),
                )
            applied.append(version)
        return applied

    def _exec_migration(self, cur, stmt: str) -> None:
        cur.execute(stmt)

    # -- reads ------------------------------------------------------------- #

    def get_state(self, did: str) -> Optional[IdentityState]:
        rows = self._q(self._sql("SELECT state FROM identities WHERE did=?"), (did,))
        return _state_from_json(rows[0][0]) if rows else None

    def get_log(self, did: str) -> list:
        rows = self._q(self._sql("SELECT event FROM events WHERE did=? ORDER BY seq"), (did,))
        return [json.loads(r[0]) for r in rows]

    def list_by_controller(self, controller: str, limit: int = MAX_PAGE, after: str = "") -> list:
        rows = self._q(
            self._sql("SELECT did, active FROM identities WHERE controller=? AND did>? ORDER BY did LIMIT ?"),
            (controller, after, min(limit, MAX_PAGE)),
        )
        return [{"did": d, "active": bool(a)} for d, a in rows]

    def list_dids(self, after: str = "", limit: int = MAX_PAGE) -> list:
        """DIDs in lexical order, for paging through the whole registry (mirroring, audits)."""
        rows = self._q(
            self._sql("SELECT did, active FROM identities WHERE did>? ORDER BY did LIMIT ?"),
            (after, min(limit, MAX_PAGE)),
        )
        return [{"did": d, "active": bool(a)} for d, a in rows]

    def stats(self) -> dict:
        ident = self._q("SELECT COUNT(*), SUM(CASE WHEN active THEN 1 ELSE 0 END) FROM identities")[0]
        events = self._q("SELECT COUNT(*) FROM events")[0][0]
        revs = self._q("SELECT COUNT(*) FROM revocations")[0][0]
        return {"identities": int(ident[0] or 0), "active": int(ident[1] or 0),
                "events": int(events or 0), "revocations": int(revs or 0)}

    def ping(self) -> bool:
        return self._q("SELECT 1")[0][0] == 1

    # -- writes ------------------------------------------------------------ #

    def append(self, event: dict, new_state: IdentityState, expected_prev_seq: Optional[int]) -> None:
        """Atomically append `event` and persist `new_state`.

        `expected_prev_seq` is None for inception. Concurrent writers racing on
        the same seq are rejected with Conflict (optimistic concurrency; the
        (did, seq) primary key is the final arbiter).
        """
        body = event["body"]
        state_json = json.dumps(dataclasses.asdict(new_state))
        try:
            with self._tx() as cur:
                self._lock_did(cur, body["did"])
                cur.execute(self._sql("SELECT MAX(seq) FROM events WHERE did=?"), (body["did"],))
                cur_seq = cur.fetchone()[0]
                if cur_seq != expected_prev_seq:
                    raise Conflict("identity changed concurrently or already exists")
                cur.execute(
                    self._sql("INSERT INTO events(did, seq, digest, event, received_at) VALUES (?,?,?,?,?)"),
                    (body["did"], body["seq"], event_digest(event), json.dumps(event), _now()),
                )
                cur.execute(
                    self._sql(
                        "INSERT INTO identities(did, controller, active, state, updated) VALUES (?,?,?,?,?) "
                        "ON CONFLICT(did) DO UPDATE SET active=excluded.active, state=excluded.state, "
                        "updated=excluded.updated"
                    ),
                    (new_state.did, new_state.controller, self._bool(new_state.active), state_json, new_state.updated),
                )
        except Conflict:
            raise
        except Exception as e:
            if self._is_unique_violation(e):
                raise Conflict("identity changed concurrently or already exists") from None
            raise

    def _lock_did(self, cur, did: str) -> None:
        pass

    def _bool(self, v: bool) -> Any:
        return int(v)

    def _is_unique_violation(self, e: Exception) -> bool:
        return False

    # -- grant revocations ------------------------------------------------- #

    def add_revocation(self, issuer: str, grant_id: str, revoked_at: int, event: dict) -> bool:
        """Returns False if it was already revoked."""
        with self._tx() as cur:
            cur.execute(
                self._sql(
                    "INSERT INTO revocations(issuer, grant_id, revoked_at, event, received_at) VALUES (?,?,?,?,?) "
                    "ON CONFLICT DO NOTHING"
                ),
                (issuer, grant_id, revoked_at, json.dumps(event), _now()),
            )
            return cur.rowcount == 1

    def revocation_events(self, pairs: list) -> dict:
        """{(issuer, grant_id): signed revocation event} for the pairs that are revoked."""
        out = {}
        for iss, gid in pairs:
            rows = self._q(self._sql("SELECT event FROM revocations WHERE issuer=? AND grant_id=?"), (iss, gid))
            if rows:
                out[(iss, gid)] = json.loads(rows[0][0])
        return out

    def revoked_among(self, pairs: list) -> list:
        found = self.revocation_events(pairs)
        return [[iss, gid] for iss, gid in pairs if (iss, gid) in found]

    # -- integrity --------------------------------------------------------- #

    def iter_dids(self) -> Iterator[str]:
        after = ""
        while True:
            page = self.list_dids(after=after, limit=MAX_PAGE)
            if not page:
                return
            for row in page:
                yield row["did"]
            after = page[-1]["did"]

    def verify_integrity(self) -> list:
        """Replay every stored log and compare with the stored state.

        Returns a list of problems (empty when the database is consistent). The
        events are self-certifying, so this detects corruption or tampering of
        the database itself.
        """
        problems = []
        for did in self.iter_dids():
            try:
                replayed = verify_log(self.get_log(did))
            except InvalidEvent as e:
                problems.append(f"{did}: log does not verify: {e}")
                continue
            stored = self.get_state(did)
            if replayed.did != did:
                problems.append(f"{did}: log belongs to {replayed.did}")
            elif stored is None or dataclasses.asdict(stored) != dataclasses.asdict(replayed):
                problems.append(f"{did}: stored state differs from the replayed log")
        return problems

    def close(self) -> None:  # pragma: no cover - overridden
        pass


class _SQLiteTx:
    def __init__(self, store: Store):
        self.store = store

    def __enter__(self):
        self.store._lock.acquire()
        self.cur = self.store._db.cursor()
        try:
            self.cur.execute("BEGIN IMMEDIATE")
        except BaseException:
            self.store._lock.release()
            raise
        return self.cur

    def __exit__(self, exc_type, exc, tb):
        try:
            self.cur.execute("COMMIT" if exc_type is None else "ROLLBACK")
        finally:
            self.store._lock.release()
        return False


class Store(_BaseStore):
    """SQLite store. All access goes through one connection guarded by a lock,
    so readers never observe another thread's uncommitted transaction."""

    migrations = _SQLITE_MIGRATIONS

    def __init__(self, path: str = ":memory:", *, auto_migrate: bool = True, check: bool = True):
        self.path = path
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10.0)
        self._db.execute("PRAGMA busy_timeout=10000")
        # Several processes opening a fresh file at once can hit SQLITE_BUSY in places the
        # busy timeout doesn't cover (switching to WAL, lock upgrades), so retry setup briefly.
        delay = 0.05
        for attempt in range(12):
            try:
                if path != ":memory:":
                    self._db.execute("PRAGMA journal_mode=WAL")
                # FULL: a committed revocation or deactivation must survive power loss.
                self._db.execute("PRAGMA synchronous=FULL")
                if auto_migrate:
                    self.migrate()
                break
            except sqlite3.OperationalError as e:
                if "locked" not in str(e) and "busy" not in str(e) or attempt == 11:
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 1.0)
        if check:
            self.check_schema()

    def _q(self, sql: str, args: tuple = ()) -> list:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def _tx(self):
        return _SQLiteTx(self)

    def _exec_migration(self, cur, stmt: str) -> None:
        try:
            cur.execute(stmt)
        except sqlite3.OperationalError as e:
            # ALTER TABLE ADD COLUMN has no IF NOT EXISTS in SQLite.
            if "duplicate column name" not in str(e):
                raise

    def _is_unique_violation(self, e: Exception) -> bool:
        return isinstance(e, sqlite3.IntegrityError)

    def close(self) -> None:
        with self._lock:
            self._db.close()


SQLiteStore = Store


class _PgTx:
    def __init__(self, store: PostgresStore):
        self.store = store

    def __enter__(self):
        self.ctx = self.store._pool.connection()
        self.conn = self.ctx.__enter__()
        self.txctx = self.conn.transaction()
        self.txctx.__enter__()
        self.cur = self.conn.cursor()
        return self.cur

    def __exit__(self, exc_type, exc, tb):
        try:
            self.cur.close()
            self.txctx.__exit__(exc_type, exc, tb)
        finally:
            self.ctx.__exit__(exc_type, exc, tb)
        return False


class PostgresStore(_BaseStore):
    """PostgreSQL store, safe for several registry replicas behind a load balancer."""

    migrations = _PG_MIGRATIONS
    placeholder = "%s"

    def __init__(self, dsn: str, *, auto_migrate: bool = True, check: bool = True, min_size: int = 1, max_size: int = 10):
        try:
            import psycopg
            from psycopg_pool import ConnectionPool
        except ImportError:  # pragma: no cover - depends on installed extras
            raise RuntimeError('Postgres support needs psycopg: pip install "agentauth[postgres]"') from None
        self._psycopg = psycopg
        self._pool = ConnectionPool(dsn, min_size=min_size, max_size=max_size, open=True,
                                    kwargs={"autocommit": True}, timeout=10.0)
        if auto_migrate:
            self.migrate()
        if check:
            self.check_schema()

    def _q(self, sql: str, args: tuple = ()) -> list:
        with self._pool.connection() as conn:
            return conn.execute(sql, args).fetchall()

    def _tx(self):
        return _PgTx(self)

    _MIGRATION_LOCK = 0x61676E7461757468  # "agntauth"

    def migrate(self) -> list:
        # Several replicas may start at once; let exactly one migrate at a time.
        with self._pool.connection() as conn:
            conn.execute("SELECT pg_advisory_lock(%s)", (self._MIGRATION_LOCK,))
            try:
                return super().migrate()
            finally:
                conn.execute("SELECT pg_advisory_unlock(%s)", (self._MIGRATION_LOCK,))

    def _lock_did(self, cur, did: str) -> None:
        # Serialize writers for one DID; other DIDs proceed in parallel.
        cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (did,))

    def _bool(self, v: bool) -> Any:
        return bool(v)

    def _is_unique_violation(self, e: Exception) -> bool:
        return isinstance(e, self._psycopg.errors.UniqueViolation)

    def close(self) -> None:
        self._pool.close()


def open_store(url: str, *, auto_migrate: bool = True, check: bool = True):
    """Open a store from a URL: ``sqlite:///rel.db``, ``sqlite:////abs/path.db``, ``sqlite:///:memory:``,
    a bare path, or ``postgresql://…``."""
    if url.startswith(("postgresql://", "postgres://")):
        return PostgresStore(url, auto_migrate=auto_migrate, check=check)
    # SQLAlchemy convention: sqlite:///relative.db, sqlite:////absolute/path.db
    if url.startswith("sqlite:///"):
        url = url[len("sqlite:///"):] or ":memory:"
    elif url.startswith("sqlite://"):
        url = url[len("sqlite://"):] or ":memory:"
    return Store(url, auto_migrate=auto_migrate, check=check)

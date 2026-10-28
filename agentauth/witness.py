"""Defences against a dishonest or broken registry.

A registry can't forge events (they're self-certifying), but it can lie by
omission:

* **Rollback / withholding** — serve an older prefix of a log, e.g. hide the
  deactivation of a compromised agent.
* **Forks (equivocation)** — serve different, conflicting histories to
  different clients. Because rotations need the pre-committed key, a genuine
  fork means the identity's own recovery key signed two different rotations,
  i.e. it was compromised; but a client must still notice instead of picking
  one at random.

This module provides two independent mitigations:

`KelPins` (and the persistent `SQLitePins`) remember, per DID, the latest
event a client has verified. Every later log must extend it. A shorter log
(rollback) or a different event at a pinned position (fork) raises
`EquivocationError`, and verifiers fail closed.

`RegistryPool` talks to several independent registries ("witnesses"). Writes
go to all of them; reads fetch the log from each, require every answer to be
a prefix of every other, and use the longest. To hide an event, *every*
registry in the pool has to withhold it.

Neither detects a registry that shows a forked log to a client that has never
seen the other branch and talks to that registry alone. That needs gossip
between clients or a transparency log; see docs/threat-model.md.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from typing import Optional

from .identity import IdentityState, InvalidEvent, event_digest, verify_log

log = logging.getLogger("agentauth.witness")


class EquivocationError(Exception):
    """A registry served a log inconsistent with another log for the same DID."""

    def __init__(self, did: str, message: str, evidence: Optional[dict] = None):
        super().__init__(f"{did}: {message}")
        self.did = did
        self.evidence = evidence or {}


def _digests(events: list) -> list:
    return [event_digest(e) for e in events]


def check_extends(did: str, older: list, newer: list) -> None:
    """Raise EquivocationError unless `newer` is `older` plus zero or more events."""
    a, b = _digests(older), _digests(newer)
    if len(b) < len(a):
        raise EquivocationError(did, f"log rolled back from {len(a)} to {len(b)} events",
                                {"seen_head": a[-1] if a else None, "served_head": b[-1] if b else None})
    for i, (x, y) in enumerate(zip(a, b, strict=False)):
        if x != y:
            raise EquivocationError(did, f"conflicting event at seq {i}", {"seq": i, "seen": x, "served": y})


def merge_logs(did: str, logs: list) -> list:
    """Given logs for one DID from several sources, return the longest one.

    Every log must be a prefix of the longest (sources may lag, but must never
    disagree). Empty logs (unknown at that source) are allowed.
    """
    nonempty = [lg for lg in logs if lg]
    if not nonempty:
        return []
    longest = max(nonempty, key=len)
    for lg in nonempty:
        check_extends(did, lg, longest)
    return longest


class KelPins:
    """In-memory pins: the newest (seq, digest) seen per DID. Thread-safe."""

    def __init__(self, max_entries: int = 1_000_000):
        self._lock = threading.Lock()
        self._pins: dict = {}
        self.max_entries = max_entries

    def get(self, did: str) -> Optional[tuple]:
        with self._lock:
            return self._pins.get(did)

    def _put(self, did: str, seq: int, digest: str) -> None:
        with self._lock:
            if did not in self._pins and len(self._pins) >= self.max_entries:
                self._pins.pop(next(iter(self._pins)))  # forget the oldest pin, not fail
            self._pins[did] = (seq, digest)

    def check_and_update(self, did: str, events: list) -> None:
        """Verify `events` extends the pinned head, then advance the pin."""
        pin = self.get(did)
        if pin is not None:
            seq, digest = pin
            if len(events) <= seq:
                raise EquivocationError(did, f"log rolled back: previously saw seq {seq}, now {len(events) - 1}",
                                        {"pinned_seq": seq, "pinned_digest": digest})
            served = event_digest(events[seq])
            if served != digest:
                raise EquivocationError(did, f"conflicting event at seq {seq}",
                                        {"seq": seq, "pinned": digest, "served": served})
        if events:
            last = len(events) - 1
            if pin is None or last > pin[0]:
                self._put(did, last, event_digest(events[last]))


class SQLitePins(KelPins):
    """Pins persisted in a local SQLite file, so detection survives restarts.

    Share one file between the worker processes of one host if you like; it
    is per-host state, not a replacement for `RegistryPool`.
    """

    def __init__(self, path: str):
        super().__init__()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10.0)
        self._db.execute("PRAGMA busy_timeout=10000")
        if path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("CREATE TABLE IF NOT EXISTS kel_pins (did TEXT PRIMARY KEY, seq INTEGER NOT NULL, digest TEXT NOT NULL)")

    def get(self, did: str) -> Optional[tuple]:
        with self._lock:
            row = self._db.execute("SELECT seq, digest FROM kel_pins WHERE did=?", (did,)).fetchone()
        return (row[0], row[1]) if row else None

    def _put(self, did: str, seq: int, digest: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO kel_pins(did, seq, digest) VALUES (?,?,?) "
                "ON CONFLICT(did) DO UPDATE SET seq=excluded.seq, digest=excluded.digest WHERE excluded.seq > kel_pins.seq",
                (did, seq, digest),
            )


class RegistryPool:
    """Several independent registries used as one, with cross-checking.

    Duck-type compatible with the parts of `RegistryClient` that resolvers,
    revocation checkers and the CLI use.

    `read_quorum` is how many registries must answer a read (a log fetch) for
    it to count; the default is all of them. Lower it to stay available when a
    witness is down, at the cost of a smaller set that has to collude to hide
    an event.
    """

    def __init__(self, registries: list, read_quorum: Optional[int] = None):
        if not registries:
            raise ValueError("RegistryPool needs at least one registry")
        self.registries = list(registries)
        self.read_quorum = len(self.registries) if read_quorum is None else read_quorum
        if not 1 <= self.read_quorum <= len(self.registries):
            raise ValueError("read_quorum must be between 1 and the number of registries")

    # -- reads ------------------------------------------------------------- #

    def _logs(self, did: str) -> list:
        """One slot per registry, in pool order: its log ([] if it doesn't know the DID), or None if it failed."""
        from .sdk import RegistryError

        slots: list = []
        errors = []
        for reg in self.registries:
            try:
                slots.append(reg.log(did))
            except RegistryError as e:
                if e.status == 404:
                    slots.append([])
                else:
                    slots.append(None)
                    errors.append(f"{getattr(reg, 'base_url', reg)}: {e}")
            except Exception as e:  # network errors etc.
                slots.append(None)
                errors.append(f"{getattr(reg, 'base_url', reg)}: {e}")
        answered = sum(s is not None for s in slots)
        if answered < self.read_quorum:
            raise RuntimeError(f"only {answered} of {len(self.registries)} registries answered: {'; '.join(errors)}")
        return slots

    def _valid_logs(self, did: str, check) -> list:
        """Each registry's log, keeping only those that verify. A registry serving an
        invalid log (e.g. one with a forged controller deactivation) is ignored rather
        than allowed to win the longest-log merge."""
        out = []
        for reg, slot in zip(self.registries, self._logs(did), strict=True):
            if not slot:
                continue
            try:
                verify_log(slot, check)
            except InvalidEvent as e:
                log.warning("ignoring an invalid log for %s from %s: %s", did, getattr(reg, "base_url", reg), e)
                continue
            out.append(slot)
        return out

    def controller_keys(self, did: str) -> set:
        """Every key `did` has held, across the pool (see sdk.controller_keys_via)."""
        merged = merge_logs(did, self._valid_logs(did, lambda d, k: True))
        return {k for _, k in verify_log(merged).history} if merged else set()

    def log(self, did: str) -> list:
        from .sdk import RegistryError, bound_controller_check

        merged = merge_logs(did, self._valid_logs(did, bound_controller_check(self)))
        if not merged:
            raise RegistryError(404, "unknown identity")
        return merged

    def verified_state(self, did: str) -> IdentityState:
        from .sdk import bound_controller_check

        state = verify_log(self.log(did), bound_controller_check(self))
        if state.did != did:
            raise InvalidEvent("registry returned a log for a different DID")
        return state

    def resolve(self, did: str) -> dict:
        return self.verified_state(did).resolution_result()

    def controlled_agents(self, did: str) -> list:
        seen: dict = {}
        for reg in self.registries:
            try:
                for row in reg.controlled_agents(did):
                    seen.setdefault(row["did"], row)
            except Exception as e:
                log.warning("controlled_agents failed at %s: %s", getattr(reg, "base_url", reg), e)
        return sorted(seen.values(), key=lambda r: r["did"])

    def revocation_proofs(self, pairs: list) -> dict:
        """{pair: [proof from each registry that claims it's revoked]}.

        Every registry's proof is kept, so one registry sending a junk proof
        can't mask a valid one from another (the checker accepts the pair if
        *any* proof verifies).
        """
        out: dict = {}
        answered = 0
        for reg in self.registries:
            try:
                claims = reg.revocation_proofs(pairs)
                answered += 1
            except Exception as e:
                log.warning("revocation check failed at %s: %s", getattr(reg, "base_url", reg), e)
                continue
            for pair, proof in claims.items():
                proofs = proof if isinstance(proof, list) else [proof]
                out.setdefault(pair, []).extend(proofs)
        if answered < self.read_quorum:
            raise RuntimeError(f"only {answered} of {len(self.registries)} registries answered a revocation check")
        return out

    def revoked(self, pairs: list) -> set:
        return set(self.revocation_proofs(pairs))

    def whoami(self, identity) -> dict:
        """Authenticated call against the first registry that answers."""
        last: Optional[Exception] = None
        for reg in self.registries:
            try:
                return reg.whoami(identity)
            except Exception as e:
                last = e
        assert last is not None  # nosec B101
        raise last

    def info(self) -> list:
        return [reg.info() for reg in self.registries]

    # -- writes ------------------------------------------------------------ #

    def _all(self, fn) -> list:
        """Run `fn(reg)` on every registry; succeed if at least one accepted.

        A registry that rejects the write or can't be reached doesn't stop the
        others (it is brought up to date by `sync` later). Only if *every*
        registry fails is the error raised — preferring a definite rejection
        (RegistryError) over a network error.
        """
        from .sdk import RegistryError

        results, errors = [], []
        for reg in self.registries:
            try:
                results.append(fn(reg))
            except Exception as e:
                errors.append(e)
        if not results:
            rejected = [e for e in errors if isinstance(e, RegistryError)]
            raise (rejected or errors)[0]
        for err in errors:
            log.warning("a registry in the pool failed a write: %s", err)
        return results

    def register(self, event: dict) -> dict:
        from .sdk import RegistryError

        def one(reg):
            try:
                return reg.register(event)
            except RegistryError as e:
                if e.status == 409:  # already there
                    return reg.resolve(event["body"]["did"])
                raise

        return self._all(one)[0]

    def submit(self, did: str, event: dict) -> dict:
        results = self._all(lambda reg: reg.submit(did, event))
        try:
            self.sync(did)  # bring lagging registries up to date
        except Exception as e:  # the write succeeded; a lagging registry can be synced later
            log.warning("post-write sync of %s failed: %s", did, e)
        return results[0]

    def revoke_grant(self, issuer, grant_id: str) -> dict:
        from .grants import make_revocation

        ev = make_revocation(issuer_did=issuer.did, issuer_key=issuer.current_key, grant_id=grant_id)
        return self._all(lambda reg: reg.submit_revocation(ev))[0]

    def sync(self, did: str) -> list:
        """Push events that some registries lack to them.

        Returns one {"registry": base_url, "pushed": n} per registry, in pool order.
        """
        from .sdk import RegistryError

        slots = self._logs(did)
        try:
            merged = self.log(did)  # only logs that verify are ever copied
        except RegistryError as e:
            if e.status != 404:
                raise
            merged = []
        pushed: list = []
        for reg, have in zip(self.registries, slots, strict=True):
            if have is None:  # unreachable right now; sync it next time
                pushed.append({"registry": getattr(reg, "base_url", str(reg)), "pushed": None})
                continue
            n = 0
            for ev in merged[len(have):]:
                try:
                    if ev["body"]["seq"] == 0:
                        reg.register(ev)
                    else:
                        reg.submit(did, ev)
                    n += 1
                except RegistryError as e:
                    if e.status != 409:
                        log.warning("sync of %s to %s failed: %s", did, getattr(reg, "base_url", reg), e)
                        break
            pushed.append({"registry": getattr(reg, "base_url", str(reg)), "pushed": n})
        return pushed

    # The SDK's lifecycle helpers work unchanged against a pool.
    def rotate(self, identity):
        from .sdk import RegistryClient

        return RegistryClient.rotate(self, identity)  # type: ignore[arg-type]

    def deactivate_self(self, identity):
        from .sdk import RegistryClient

        return RegistryClient.deactivate_self(self, identity)  # type: ignore[arg-type]

    def deactivate_controlled(self, controller, agent_did: str) -> dict:
        from .sdk import RegistryClient

        return RegistryClient.deactivate_controlled(self, controller, agent_did)  # type: ignore[arg-type]

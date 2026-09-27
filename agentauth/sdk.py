"""Client SDK: create identities, talk to the registry, sign and verify requests."""

from __future__ import annotations

import dataclasses
import os
import threading
import time
from pathlib import Path
from typing import Optional

import httpx

from .crypto import KeyPair
from .grants import HEADER as GRANT_HEADER
from .grants import DEFAULT_TTL, GrantChain, issue, make_revocation
from .limits import Limits
from .httpsig import sign_request
from .identity import (
    IdentityState,
    make_deactivation,
    make_inception,
    make_rotation,
    verify_inception,
    verify_log,
)
from .keystore import read_key_file, write_key_file


def _default_passphrase() -> Optional[str]:
    return os.environ.get("AGENTAUTH_PASSPHRASE") or None


class AgentIdentity:
    """An agent's local view of its own identity plus its private keys.

    `recovery_key` (the pre-committed next key) may be None when the identity
    was loaded without its recovery file — enough to authenticate, not enough
    to rotate.
    """

    def __init__(self, state: IdentityState, current_key: KeyPair, recovery_key: Optional[KeyPair]):
        self.state = state
        self.current_key = current_key
        self.recovery_key = recovery_key
        self._pending: Optional[tuple] = None

    # -- creation ---------------------------------------------------------- #

    @classmethod
    def create(cls, *, name: str = "", controller: Optional["AgentIdentity"] = None, meta: Optional[dict] = None):
        """Generate keys and a signed inception event. Returns (identity, event)."""
        current, nxt = KeyPair.generate(), KeyPair.generate()
        meta = dict(meta or {})
        if name:
            meta["name"] = name
        event = make_inception(
            current,
            nxt,
            controller=controller.did if controller else None,
            controller_key=controller.current_key if controller else None,
            meta=meta,
        )
        state = verify_inception(event, lambda d, k: True)
        return cls(state, current, nxt), event

    @property
    def did(self) -> str:
        return self.state.did

    @property
    def kid(self) -> str:
        return self.state.key_id

    # -- lifecycle events (not applied until the registry accepts them) ---- #

    def prepare_rotation(self) -> dict:
        if self.recovery_key is None:
            raise RuntimeError("rotation needs the recovery key file")
        new_next = KeyPair.generate()
        event = make_rotation(self.state, self.recovery_key, new_next)
        self._pending = ("rotation", event, new_next)
        return event

    def prepare_self_deactivation(self) -> dict:
        if self.recovery_key is None:
            raise RuntimeError("self-deactivation needs the recovery key file")
        event = make_deactivation(self.state, self.did, self.recovery_key)
        self._pending = ("deactivation", event, None)
        return event

    def prepare_deactivation_of(self, child_state: IdentityState) -> dict:
        """As a controller, deactivate an agent you control."""
        if child_state.controller != self.did:
            raise ValueError("this identity is not the agent's controller")
        return make_deactivation(child_state, self.did, self.current_key)

    def commit(self, accepted_state: IdentityState) -> None:
        """Apply a pending event after the registry accepted it."""
        if not self._pending:
            raise RuntimeError("nothing pending")
        kind, _, new_next = self._pending
        if kind == "rotation":
            self.current_key, self.recovery_key = self.recovery_key, new_next
        self.state = accepted_state
        self._pending = None

    # -- request signing --------------------------------------------------- #

    def authorization(self, method: str, url: str, body: bytes = b"", grants: str = "") -> str:
        if not self.state.active:
            raise RuntimeError("identity is deactivated")
        return sign_request(
            did=self.did, kid=self.kid, key=self.current_key, method=method, url=url, body=body, grants=grants
        )

    def httpx_auth(self, grants: Optional[GrantChain] = None) -> "AgentSigAuth":
        """httpx auth that signs requests and, if given, presents a grant chain."""
        return AgentSigAuth(self, grants)

    # -- capability grants ------------------------------------------------- #

    def grant(
        self,
        subject: str,
        scopes: list,
        audiences: list,
        *,
        ttl: int = DEFAULT_TTL,
        depth: int = 0,
        parent: Optional[GrantChain] = None,
        limits: Optional[Limits] = None,
    ) -> GrantChain:
        """Authorize `subject` to act with `scopes` at `audiences`.

        Without `parent`, this identity acts as a principal and issues a root
        grant. With `parent` (a chain issued *to* this identity), it delegates a
        narrower slice of that authority. `depth` is how many further hops the
        subject may delegate. `limits` (see agentauth.limits.Limits.build)
        restricts resources, spend, rate and total uses; when delegating,
        anything you leave unset is inherited from the parent.
        """
        if not self.state.active:
            raise RuntimeError("identity is deactivated")
        return issue(
            issuer_did=self.did,
            issuer_kid=self.kid,
            issuer_key=self.current_key,
            subject=subject,
            scopes=scopes,
            audiences=audiences,
            ttl=ttl,
            depth=depth,
            parent=parent,
            limits=limits,
        )

    # -- persistence ------------------------------------------------------- #

    def save(self, directory: Path, name: str, passphrase: Optional[str] = None, recovery_dir: Optional[Path] = None):
        passphrase = passphrase if passphrase is not None else _default_passphrase()
        directory = Path(directory).expanduser()
        extra = {"state": dataclasses.asdict(self.state)}
        write_key_file(directory / f"{name}.key.json", did=self.did, role="current", key=self.current_key, extra=extra, passphrase=passphrase)
        if self.recovery_key is not None:
            rdir = Path(recovery_dir).expanduser() if recovery_dir else directory
            write_key_file(rdir / f"{name}.recovery.json", did=self.did, role="recovery", key=self.recovery_key, extra={}, passphrase=passphrase)

    @classmethod
    def load(cls, directory: Path, name: str, passphrase: Optional[str] = None, recovery_dir: Optional[Path] = None):
        passphrase = passphrase if passphrase is not None else _default_passphrase()
        directory = Path(directory).expanduser()
        doc, current = read_key_file(directory / f"{name}.key.json", passphrase)
        st = dict(doc["state"])
        st["history"] = [tuple(h) for h in st["history"]]
        state = IdentityState(**st)
        rpath = (Path(recovery_dir).expanduser() if recovery_dir else directory) / f"{name}.recovery.json"
        recovery = None
        if rpath.exists():
            rdoc, recovery = read_key_file(rpath, passphrase)
            if rdoc["did"] != state.did:
                raise ValueError("recovery file belongs to a different DID")
        return cls(state, current, recovery)


class AgentSigAuth(httpx.Auth):
    """httpx auth hook: signs every outgoing request with the agent's key."""

    requires_request_body = True

    def __init__(self, identity: AgentIdentity, grants: Optional[GrantChain] = None):
        self.identity = identity
        self.grants = grants.encode() if grants is not None else ""

    def auth_flow(self, request: httpx.Request):
        if self.grants:
            request.headers[GRANT_HEADER] = self.grants
        request.headers["Authorization"] = self.identity.authorization(
            request.method, str(request.url), request.content, self.grants
        )
        yield request


class RegistryError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(f"{status}: {detail}")
        self.status, self.detail = status, detail


class RegistryClient:
    def __init__(self, base_url: str, *, client: Optional[httpx.Client] = None, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self._http = client or httpx.Client(base_url=self.base_url, timeout=timeout)

    def _check(self, r: httpx.Response) -> dict:
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except ValueError:
                detail = r.text
            raise RegistryError(r.status_code, str(detail))
        return r.json()

    # -- lifecycle --------------------------------------------------------- #

    def register(self, event: dict) -> dict:
        return self._check(self._http.post("/v1/identities", json=event))

    def submit(self, did: str, event: dict) -> dict:
        return self._check(self._http.post(f"/v1/identities/{did}/events", json=event))

    def rotate(self, identity: AgentIdentity) -> AgentIdentity:
        event = identity.prepare_rotation()
        self.submit(identity.did, event)
        identity.commit(self.verified_state(identity.did))
        return identity

    def deactivate_self(self, identity: AgentIdentity) -> AgentIdentity:
        event = identity.prepare_self_deactivation()
        self.submit(identity.did, event)
        identity.commit(self.verified_state(identity.did))
        return identity

    def deactivate_controlled(self, controller: AgentIdentity, agent_did: str) -> dict:
        child = self.verified_state(agent_did)
        return self.submit(agent_did, controller.prepare_deactivation_of(child))

    # -- resolution -------------------------------------------------------- #

    def resolve(self, did: str) -> dict:
        return self._check(self._http.get(f"/v1/identities/{did}"))

    def log(self, did: str) -> list:
        return self._check(self._http.get(f"/v1/identities/{did}/log"))["events"]

    def controlled_agents(self, did: str) -> list:
        return self._check(self._http.get(f"/v1/identities/{did}/agents"))["agents"]

    def verified_state(self, did: str) -> IdentityState:
        """Fetch the full event log and replay it locally — trusts no one."""
        state = verify_log(self.log(did))
        if state.did != did:
            raise ValueError("registry returned a log for a different DID")
        return state

    def whoami(self, identity: AgentIdentity) -> dict:
        return self._check(self._http.get("/v1/whoami", auth=identity.httpx_auth()))

    # -- grant revocation -------------------------------------------------- #

    def revoke_grant(self, issuer: AgentIdentity, grant_id: str) -> dict:
        """Revoke a grant you issued. Everything delegated beneath it dies too."""
        ev = make_revocation(issuer_did=issuer.did, issuer_key=issuer.current_key, grant_id=grant_id)
        return self._check(self._http.post("/v1/revocations", json=ev))

    def revoked(self, pairs: list) -> set:
        r = self._check(self._http.post("/v1/revocations/check", json={"grants": [list(p) for p in pairs]}))
        return {tuple(p) for p in r["revoked"]}


class RegistryRevocationChecker:
    """For relying parties: asks the registry whether grants are revoked.

    Revoked results are cached forever (revocation is permanent); "not revoked"
    results for `ttl` seconds, which bounds how long a revoked grant can still
    be honoured. Use ttl=0 for immediate effect at the cost of a registry call
    per request.
    """

    def __init__(self, registry: RegistryClient, ttl: float = 10.0):
        self.registry, self.ttl = registry, ttl
        self._revoked: set = set()
        self._ok: dict = {}
        self._lock = threading.Lock()

    def __call__(self, pairs: list) -> set:
        now = time.time()
        pairs = [tuple(p) for p in pairs]
        with self._lock:
            hits = {p for p in pairs if p in self._revoked}
            if hits:
                return hits
            unknown = [p for p in pairs if self._ok.get(p, 0) <= now]
        if not unknown:
            return set()
        revoked = self.registry.revoked(unknown)
        with self._lock:
            self._revoked |= revoked
            for p in unknown:
                if p not in revoked:
                    self._ok[p] = now + self.ttl
        return revoked


class RegistryKeyResolver:
    """For relying parties: resolves an agent's current key via a registry, with a short cache.

    Uses full log replay by default so a compromised registry can't substitute keys.
    """

    def __init__(self, registry: RegistryClient, ttl: float = 30.0, verify_logs: bool = True):
        self.registry, self.ttl, self.verify_logs = registry, ttl, verify_logs
        self._cache: dict = {}
        self._lock = threading.Lock()

    def __call__(self, did: str) -> Optional[tuple]:
        now = time.time()
        with self._lock:
            hit = self._cache.get(did)
            if hit and hit[0] > now:
                return hit[1]
        try:
            if self.verify_logs:
                st = self.registry.verified_state(did)
                value = (st.key, st.key_id) if st.active and st.key else None
            else:
                doc = self.registry.resolve(did)
                vms = doc["didDocument"]["verificationMethod"]
                value = (vms[0]["publicKeyMultibase"], vms[0]["id"]) if vms else None
        except RegistryError as e:
            if e.status == 404:
                value = None
            else:
                raise
        with self._lock:
            self._cache[did] = (now + self.ttl, value)
        return value

    def invalidate(self, did: str) -> None:
        with self._lock:
            self._cache.pop(did, None)

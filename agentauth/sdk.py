"""Client SDK: create identities, talk to the registry, sign and verify requests."""

from __future__ import annotations

import dataclasses
import logging
import os
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Optional, Union
from urllib.parse import quote

import httpx

from .crypto import KeyPair, Signer, key_commitment, verify
from .grants import DEFAULT_TTL, GrantChain, GrantError, issue, make_revocation, parse_revocation
from .grants import HEADER as GRANT_HEADER
from .httpsig import sign_request
from .identity import (
    IdentityState,
    event_digest,
    is_agent_did,
    make_deactivation,
    make_inception,
    make_rotation,
    verify_inception,
    verify_log,
)
from .keystore import ENC_V2, read_key_file, remove_key_file, write_key_file
from .limits import Limits
from .witness import EquivocationError, KelPins

log = logging.getLogger("agentauth.sdk")
USER_AGENT = "agentauth-python"


def _default_passphrase() -> Optional[str]:
    """AGENTAUTH_PASSPHRASE, or the contents of the file named by AGENTAUTH_PASSPHRASE_FILE."""
    path = os.environ.get("AGENTAUTH_PASSPHRASE_FILE")
    if path:
        with open(path, encoding="utf-8") as f:
            return f.read().rstrip("\r\n") or None
    return os.environ.get("AGENTAUTH_PASSPHRASE") or None


class AgentIdentity:
    """An agent's local view of its own identity plus its private keys.

    `recovery_key` (the pre-committed next key) may be None when the identity
    was loaded without its recovery file — enough to authenticate, not enough
    to rotate.
    """

    def __init__(self, state: IdentityState, current_key: Signer, recovery_key: Optional[Signer]):
        if state.active and state.key != current_key.public_multikey:
            raise ValueError("current key does not match the identity's current public key")
        self.state = state
        self.current_key = current_key
        self.recovery_key = recovery_key
        self._pending: Optional[tuple] = None
        self.pending_next_key: Optional[Signer] = None  # loaded from <name>.pending.json, see rotate_and_save
        self._pending_authenticated = False  # was that file encrypted (v2) under this identity's passphrase?

    # -- creation ---------------------------------------------------------- #

    @classmethod
    def create(cls, *, name: str = "", controller: Optional[AgentIdentity] = None, meta: Optional[dict] = None):
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

    def prepare_rotation(self, new_next: Optional[Signer] = None) -> dict:
        """Build a rotation to the pre-committed key. `new_next` defaults to a fresh key
        (pass an HSM/KMS-backed `Signer` to keep the next recovery key outside this process)."""
        if self.recovery_key is None:
            raise RuntimeError("rotation needs the recovery key file")
        if not self.state.active:
            raise RuntimeError("identity is deactivated")
        new_next = new_next or KeyPair.generate()
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
        """Apply a pending event after the registry accepted it.

        Refuses unless `accepted_state` (normally a freshly verified log) really
        contains the pending event, so a registry that dropped it can't make
        the SDK swap to keys the rest of the world doesn't know about.
        """
        if not self._pending:
            raise RuntimeError("nothing pending")
        kind, event, new_next = self._pending
        if accepted_state.did != self.did or accepted_state.seq != event["body"]["seq"] \
                or accepted_state.last_digest != event_digest(event):
            raise RuntimeError("the registry's log does not contain the submitted event; not committing")
        if kind == "rotation":
            assert self.recovery_key is not None  # prepare_rotation checked it  # nosec B101
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

    def httpx_auth(self, grants: Optional[GrantChain] = None) -> AgentSigAuth:
        """httpx auth that signs requests and, if given, presents a grant chain."""
        return AgentSigAuth(self, grants)

    def headers(self, method: str, url: str, body: bytes = b"", grants: Optional[GrantChain] = None) -> dict:
        """Headers for any HTTP client: Authorization, plus AgentGrant when presenting a chain."""
        enc = grants.encode() if grants is not None else ""
        h = {"Authorization": self.authorization(method, url, body, enc)}
        if enc:
            h[GRANT_HEADER] = enc
        return h

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

    @staticmethod
    def _paths(directory, name: str, recovery_dir) -> tuple:
        if not name or "/" in name or "\\" in name or name.startswith("."):
            raise ValueError(f"invalid identity name {name!r}")
        d = Path(directory).expanduser()
        r = Path(recovery_dir).expanduser() if recovery_dir else d
        return d / f"{name}.key.json", r / f"{name}.recovery.json", r / f"{name}.pending.json"

    def save(self, directory: Path, name: str, passphrase: Optional[str] = None, recovery_dir: Optional[Path] = None,
             *, overwrite: bool = True):
        """Write the key files. Pass ``overwrite=False`` when creating a new identity: an
        existing key or recovery file is then never replaced (FileExistsError), so a typo'd
        name can't destroy another identity's only recovery key."""
        passphrase = passphrase if passphrase is not None else _default_passphrase()
        key_path, rec_path, pending_path = self._paths(directory, name, recovery_dir)
        if not overwrite:
            for p in (key_path, rec_path, pending_path):
                if p.exists():
                    raise FileExistsError(f"{p} already exists")
        extra = {"state": dataclasses.asdict(self.state)}
        # Order matters for crash recovery (see rotate_and_save): current key first, then recovery.
        write_key_file(key_path, did=self.did, role="current", key=self.current_key, extra=extra,
                       passphrase=passphrase, overwrite=overwrite)
        if self.recovery_key is not None:
            write_key_file(rec_path, did=self.did, role="recovery", key=self.recovery_key, extra={},
                           passphrase=passphrase, overwrite=overwrite)

    @classmethod
    def load(cls, directory: Path, name: str, passphrase: Optional[str] = None, recovery_dir: Optional[Path] = None):
        passphrase = passphrase if passphrase is not None else _default_passphrase()
        key_path, rpath, ppath = cls._paths(directory, name, recovery_dir)
        doc, current = read_key_file(key_path, passphrase)
        if doc.get("role") != "current":
            raise ValueError(f"{key_path} is not a current-key file")
        st = dict(doc["state"])
        st["history"] = [tuple(h) for h in st["history"]]
        state = IdentityState(**st)
        if doc["did"] != state.did:
            raise ValueError("key file DID does not match its recorded state")
        recovery = None
        if rpath.exists():
            rdoc, recovery = read_key_file(rpath, passphrase)
            if rdoc["did"] != state.did or rdoc.get("role") != "recovery":
                raise ValueError("recovery file belongs to a different DID")
        ident = cls(state, current, recovery)
        if ppath.exists():
            pdoc, pending = read_key_file(ppath, passphrase)
            if pdoc["did"] != state.did or pdoc.get("role") != "pending-next":
                raise ValueError("pending rotation file belongs to a different DID")
            ident.pending_next_key = pending
            ident._pending_authenticated = (pdoc.get("secret") or {}).get("enc") == ENC_V2
            log.warning("%s has an unfinished rotation; run rotate again to complete it", name)
        return ident

    def rotate_and_save(
        self,
        registry: Any,
        directory: Path,
        name: str,
        passphrase: Optional[str] = None,
        recovery_dir: Optional[Path] = None,
    ) -> AgentIdentity:
        """Rotate and persist keys without ever risking the loss of the new recovery key.

        1. The new next key is written to ``<name>.pending.json`` *before* the
           rotation is submitted.
        2. The rotation is submitted, and the registry's log is replayed to
           confirm it.
        3. The key files are rewritten and the pending file removed.

        If the process dies anywhere in between, calling this again resumes:
        it checks whether the registry already applied the rotation and
        finishes it with the saved pending key instead of generating a new one.

        If the registry's verified log already commits to the pending key, the
        rotation is completed with it. If not (the rotation apparently never
        reached the registry), the pending key is reused only when it was read
        from an authenticated file: one encrypted with this identity's
        passphrase in the v2 format, which binds it to this DID and role, so
        nobody without the passphrase could have planted it. An unauthenticated
        (plaintext or older-format) pending file is moved aside, never deleted,
        and a fresh key is used: adopting it would let anyone able to write to
        the recovery directory choose this identity's next key, while keeping
        the file means that if the registry did commit to it after all (a
        lagging read), the key can still be recovered by hand.

        A new pending file is created exclusively; if one appears concurrently,
        this call stops. Two racing rotations of one identity can't both be
        accepted: the registry takes only one event per sequence number.
        """
        passphrase = passphrase if passphrase is not None else _default_passphrase()
        _, _, ppath = self._paths(directory, name, recovery_dir)
        if self.recovery_key is None:
            raise RuntimeError("rotation needs the recovery key file")

        if self.pending_next_key is not None:
            pending = self.pending_next_key
            remote = registry.verified_state(self.did)
            if remote.active and remote.next == key_commitment(pending.public_multikey):
                # The earlier rotation went through (the registry now commits to the pending
                # key). Depending on where we crashed, the key it made current is either still
                # our recovery key, or already saved as our current key.
                if remote.key == self.recovery_key.public_multikey:
                    self.current_key = self.recovery_key
                elif remote.key != self.current_key.public_multikey:
                    raise RuntimeError("registry state diverged from the local key files; refusing to rotate")
                self.recovery_key, self.state, self.pending_next_key = pending, remote, None
                self.save(directory, name, passphrase, recovery_dir)
                remove_key_file(ppath)
                return self
            if (remote.seq != self.state.seq or remote.key != self.current_key.public_multikey
                    or remote.next != key_commitment(self.recovery_key.public_multikey)):
                raise RuntimeError("registry state diverged from the local key files; refusing to rotate")
            if self._pending_authenticated:
                new_next: Signer = pending  # not applied: retry with the same (authentic) saved key
            else:
                aside = ppath.with_name(f"{ppath.name}.unadopted-{int(time.time())}")
                log.warning("%s: pending rotation key file is not authenticated (unencrypted or an older format) and "
                            "the registry hasn't committed to it; moved it to %s and using a fresh key", name, aside)
                os.replace(ppath, aside)
                self.pending_next_key = None

        if self.pending_next_key is None:
            new_next = KeyPair.generate()
            self.prepare_rotation(new_next)
            try:
                write_key_file(ppath, did=self.did, role="pending-next", key=new_next, extra={},
                               passphrase=passphrase, overwrite=False)
            except FileExistsError:
                self._pending = None
                raise RuntimeError(f"{ppath} appeared while rotating: another rotation of this identity is in "
                                   "progress") from None
            self.pending_next_key = new_next
        event = self.prepare_rotation(new_next)
        registry.submit(self.did, event)
        self.commit(registry.verified_state(self.did))
        self.pending_next_key = None
        self.save(directory, name, passphrase, recovery_dir)
        remove_key_file(ppath)
        return self

    def refresh(self, registry: Any) -> AgentIdentity:
        """Re-read this identity's state from the registry's (verified) log."""
        remote = registry.verified_state(self.did)
        if remote.active and remote.key != self.current_key.public_multikey:
            raise RuntimeError("the registry says this identity uses a different key; were these keys rotated elsewhere?")
        self.state = remote
        return self


class AgentSigAuth(httpx.Auth):
    """Signs every outgoing request with the agent's key (and presents a grant chain, if any).

    Works with both `httpx` and `httpx2` clients: httpx uses it as an
    `httpx.Auth` (via `auth_flow`), while httpx2 — which doesn't recognise
    httpx's Auth class — accepts any callable that takes and returns a request
    (via `__call__`).
    """

    requires_request_body = True

    def __init__(self, identity: AgentIdentity, grants: Optional[GrantChain] = None):
        self.identity = identity
        self.grants = grants.encode() if grants is not None else ""

    def sign(self, request):
        """Add the AgentSig (and AgentGrant) headers to an httpx or httpx2 request, in place."""
        if self.grants:
            request.headers[GRANT_HEADER] = self.grants
        request.headers["Authorization"] = self.identity.authorization(
            request.method, str(request.url), request.content, self.grants
        )
        return request

    def auth_flow(self, request: httpx.Request):
        yield self.sign(request)

    def __call__(self, request):
        return self.sign(request)


class RegistryError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(f"{status}: {detail}")
        self.status, self.detail = status, detail


def _did_path(did: str) -> str:
    if not is_agent_did(did):
        raise ValueError(f"not a did:agent identifier: {did[:80]!r}")
    return quote(did, safe=":")


def controller_keys_via(registry: Any, did: str) -> set:
    """Every key `did` has ever held, from its verified log (empty if the registry doesn't know it).

    Trusting embedded controller signatures is fine *here*: a forged controller
    signature can only add a deactivation to the controller's own log, and a
    deactivation adds no key to a history. Rotations need the pre-committed key.
    """
    own = getattr(registry, "controller_keys", None)
    if own is not None:
        return own(did)
    try:
        events = registry.log(did)
    except RegistryError as e:
        if e.status == 404:
            return set()
        raise
    st = verify_log(events)
    if st.did != did:
        raise ValueError("registry returned a log for a different DID")
    return {k for _, k in st.history}


def bound_controller_check(registry: Any):
    """A ControllerKeyCheck that only accepts keys the controller has actually held.

    The default for `verify_log` checks a controller's signature against the key
    embedded in the event, which a dishonest registry could fabricate to forge a
    kill-switch deactivation (or a controller relationship). Relying parties use
    this check instead.
    """
    cache: dict = {}

    def check(controller: str, key: str) -> bool:
        if controller not in cache:
            cache[controller] = controller_keys_via(registry, controller)
        return key in cache[controller]

    return check


class RegistryClient:
    """HTTP client for one registry.

    Idempotent reads are retried (`retries` times, with backoff) on connection
    errors and 502/503/504. Writes are never retried automatically.
    """

    def __init__(
        self,
        base_url: str,
        *,
        client: Optional[httpx.Client] = None,
        timeout: float = 10.0,
        retries: int = 2,
        registration_token: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.retries = retries
        self.registration_token = registration_token or os.environ.get("AGENTAUTH_REGISTRATION_TOKEN") or None
        self._http = client or httpx.Client(base_url=self.base_url, timeout=timeout,
                                            headers={"User-Agent": USER_AGENT})

    def _check(self, r) -> dict:
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except ValueError:
                detail = r.text
            raise RegistryError(r.status_code, str(detail))
        try:
            return r.json()
        except ValueError:
            raise RegistryError(r.status_code, "registry returned a non-JSON response") from None

    def _get(self, path: str, **kw) -> dict:
        delay = 0.2
        for attempt in range(self.retries + 1):
            try:
                r = self._http.get(path, **kw)
                if r.status_code in (502, 503, 504) and attempt < self.retries:
                    raise httpx.TransportError(f"registry answered {r.status_code}")
                return self._check(r)
            except httpx.TransportError:
                if attempt >= self.retries:
                    raise
                time.sleep(delay)
                delay *= 2
        raise AssertionError("unreachable")  # pragma: no cover

    def _post(self, path: str, body: Any, headers: Optional[dict] = None) -> dict:
        return self._check(self._http.post(path, json=body, headers=headers))

    # -- lifecycle --------------------------------------------------------- #

    def register(self, event: dict) -> dict:
        headers = {"X-AgentAuth-Registration-Token": self.registration_token} if self.registration_token else None
        return self._post("/v1/identities", event, headers)

    def submit(self, did: str, event: dict) -> dict:
        return self._post(f"/v1/identities/{_did_path(did)}/events", event)

    def rotate(self, identity: AgentIdentity) -> AgentIdentity:
        """Rotate in memory. Prefer `identity.rotate_and_save(...)`, which can't lose the new recovery key."""
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

    def info(self) -> dict:
        return self._get("/v1/info")

    def resolve(self, did: str) -> dict:
        return self._get(f"/v1/identities/{_did_path(did)}")

    def log(self, did: str) -> list:
        data = self._get(f"/v1/identities/{_did_path(did)}/log")
        events = data.get("events") if isinstance(data, dict) else None
        if not isinstance(events, list):
            raise RegistryError(502, "registry returned a malformed log")
        return events

    def controlled_agents(self, did: str, max_agents: int = 100_000) -> list:
        """Every agent controlled by `did`, following pagination. A registry that keeps
        returning pages (or loops `next`) can't make this run forever: it stops with
        an error after `max_agents` entries or a repeated cursor."""
        out: list = []
        after: Optional[str] = ""
        seen: set = set()
        while True:
            page = self._get(f"/v1/identities/{_did_path(did)}/agents", params={"after": after, "limit": 1000})
            agents = page.get("agents") if isinstance(page, dict) else None
            if not isinstance(agents, list):
                raise RegistryError(502, "registry returned a malformed page")
            out += agents
            after = page.get("next")
            if not after:
                return out
            if after in seen or len(out) > max_agents:
                raise RegistryError(502, "registry pagination did not terminate")
            seen.add(after)

    def list_identities(self, after: str = "", limit: int = 100) -> dict:
        return self._get("/v1/identities", params={"after": after, "limit": limit})

    def verified_state(self, did: str) -> IdentityState:
        """Fetch the full event log and replay it locally — trusts no one.

        Controller signatures are checked against the controller's own key history.
        """
        state = verify_log(self.log(did), bound_controller_check(self))
        if state.did != did:
            raise ValueError("registry returned a log for a different DID")
        return state

    def whoami(self, identity: AgentIdentity) -> dict:
        return self._get("/v1/whoami", auth=identity.httpx_auth())

    # -- grant revocation -------------------------------------------------- #

    def submit_revocation(self, event: dict) -> dict:
        return self._post("/v1/revocations", event)

    def revoke_grant(self, issuer: AgentIdentity, grant_id: str) -> dict:
        """Revoke a grant you issued. Everything delegated beneath it dies too."""
        return self.submit_revocation(
            make_revocation(issuer_did=issuer.did, issuer_key=issuer.current_key, grant_id=grant_id))

    def revocation_proofs(self, pairs: list) -> dict:
        """{(issuer, grant_id): signed revocation event-or-None} for the pairs the registry says are revoked.

        The value is None when the registry claims a revocation but sent no
        proof (registries older than v0.4).
        """
        r = self._post("/v1/revocations/check", {"grants": [list(p) for p in pairs]})
        revoked = [tuple(p) for p in r.get("revoked", [])]
        proofs = r.get("proofs")
        out: dict = {}
        for i, p in enumerate(revoked):
            out[p] = proofs[i] if isinstance(proofs, list) and i < len(proofs) else None
        return out

    def revoked(self, pairs: list) -> set:
        r = self._post("/v1/revocations/check", {"grants": [list(p) for p in pairs]})
        return {tuple(p) for p in r["revoked"]}


Registry = Union[RegistryClient, Any]  # a RegistryClient or a witness.RegistryPool


class RegistryRevocationChecker:
    """For relying parties: asks the registry whether grants are revoked.

    Revoked results are cached forever (revocation is permanent); "not revoked"
    results for `ttl` seconds, which bounds how long a revoked grant can still
    be honoured. Use ttl=0 for immediate effect at the cost of a registry call
    per request.

    Proofs: from v0.4 the registry returns the issuer-signed revocation for
    every grant it reports as revoked. With `verify_proofs=True` (the default)
    each one is checked against the issuer's key history (from its verified
    log), so a registry can't revoke grants nobody revoked. What happens to a
    claim *without* a valid proof is `on_unproven`:

    * ``"deny"`` (default, fail closed): treat it as revoked anyway, and log it.
    * ``"ignore"``: only verified proofs count. Use this when an attacker who
      controls the registry denying service is a bigger risk than an old
      registry without proof support.

    A registry can still *hide* a revocation. Run several (`RegistryPool`) to
    make that require collusion.
    """

    def __init__(self, registry: Registry, ttl: float = 10.0, *, verify_proofs: bool = True,
                 on_unproven: str = "deny", max_entries: int = 100_000):
        if on_unproven not in ("deny", "ignore"):
            raise ValueError("on_unproven must be 'deny' or 'ignore'")
        self.registry, self.ttl = registry, ttl
        self.verify_proofs, self.on_unproven = verify_proofs, on_unproven
        self.max_entries = max_entries
        self._revoked: set = set()
        self._ok: OrderedDict = OrderedDict()
        self._lock = threading.Lock()
        self.unproven_claims = 0

    def _proof_ok(self, pair: tuple, proof: Any) -> bool:
        iss, gid = pair
        try:
            body = parse_revocation(proof)
        except GrantError:
            return False
        if body["iss"] != iss or body["grant"] != gid:
            return False
        from .crypto import canonical_json

        state = self.registry.verified_state(iss)
        msg = canonical_json(body)
        return any(verify(k, msg, proof["sig"]) for _, k in state.history)

    def _ask(self, pairs: list) -> set:
        if not self.verify_proofs:
            return set(self.registry.revoked(pairs))
        claims = self.registry.revocation_proofs(pairs)
        out = set()
        for pair, proof in claims.items():
            if pair not in pairs:
                continue
            # A RegistryPool returns every registry's proof; one valid proof is enough.
            candidates = proof if isinstance(proof, list) else [proof]
            if any(p is not None and self._proof_ok(pair, p) for p in candidates):
                out.add(pair)
                continue
            self.unproven_claims += 1
            log.warning("registry claims %s is revoked without a valid proof (%s)", pair, self.on_unproven)
            if self.on_unproven == "deny":
                out.add(pair)
        return out

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
        revoked = self._ask(unknown)
        with self._lock:
            self._revoked |= revoked
            for p in unknown:
                if p not in revoked and self.ttl > 0:
                    self._ok[p] = now + self.ttl
                    self._ok.move_to_end(p)
            while len(self._ok) > self.max_entries:
                self._ok.popitem(last=False)
        return revoked


class RegistryKeyResolver:
    """For relying parties: resolves an agent's current key via a registry, with a short cache.

    * Replays the full log by default (`verify_logs=True`), so a compromised
      registry can't substitute keys.
    * Pins every log it has verified (`pins`, in memory by default; pass
      `witness.SQLitePins(path)` to persist). A registry that later serves a
      shorter log (hiding events) or a conflicting one raises
      `EquivocationError`, which verifiers turn into a 503.
    * Accepts a `witness.RegistryPool` instead of a single registry to
      cross-check several.
    * Forced refreshes (when a caller presents a newer kid than cached) are
      limited to one per DID per `min_refresh_interval` seconds, so callers
      can't use them to hammer the registry.
    """

    def __init__(
        self,
        registry: Registry,
        ttl: float = 30.0,
        verify_logs: bool = True,
        *,
        pins: Optional[KelPins] = None,
        max_entries: int = 100_000,
        min_refresh_interval: float = 1.0,
    ):
        self.registry, self.ttl, self.verify_logs = registry, ttl, verify_logs
        self.pins = pins if pins is not None else KelPins()
        self.max_entries = max_entries
        self.min_refresh_interval = min_refresh_interval
        self._cache: OrderedDict = OrderedDict()
        self._forced: dict = {}
        self._lock = threading.Lock()
        # Fetch, pin check and cache write for one DID happen under one of these
        # (striped) locks, so concurrent requests can't interleave them.
        self._did_locks = [threading.Lock() for _ in range(64)]

    def _fetch_verified(self, did: str) -> Optional[tuple]:
        events = self.registry.log(did)
        st = verify_log(events, bound_controller_check(self.registry))
        if st.did != did:
            raise ValueError("registry returned a log for a different DID")
        self.pins.check_and_update(did, events)
        return (st.key, st.key_id) if st.active and st.key else None

    def _fetch(self, did: str) -> Optional[tuple]:
        try:
            if self.verify_logs:
                try:
                    return self._fetch_verified(did)
                except EquivocationError as e:
                    if "rolled back" not in str(e):
                        raise
                    # A registry behind a load balancer may briefly serve a lagging replica.
                    # Ask once more before raising the alarm.
                    time.sleep(0.05)
                    return self._fetch_verified(did)
            doc = self.registry.resolve(did)
            vms = doc["didDocument"]["verificationMethod"]
            return (vms[0]["publicKeyMultibase"], vms[0]["id"]) if vms else None
        except RegistryError as e:
            if e.status == 404:
                if self.verify_logs and self.pins.get(did) is not None:
                    raise EquivocationError(did, "registry no longer knows an identity it served before") from None
                return None
            raise
        except EquivocationError as e:
            log.critical("registry equivocation detected: %s %s", e, e.evidence)
            raise

    def __call__(self, did: str) -> Optional[tuple]:
        now = time.time()
        with self._lock:
            hit = self._cache.get(did)
            if hit and hit[0] > now:
                return hit[1]
        with self._did_locks[hash(did) % len(self._did_locks)]:
            with self._lock:  # another thread may have just fetched it
                hit = self._cache.get(did)
                if hit and hit[0] > time.time():
                    return hit[1]
            value = self._fetch(did)
            with self._lock:
                if self.ttl > 0:
                    self._cache[did] = (time.time() + self.ttl, value)
                    self._cache.move_to_end(did)
                    while len(self._cache) > self.max_entries:
                        self._cache.popitem(last=False)
        return value

    def history(self, did: str) -> list:
        """Every key `did` has held, as [(seq, multikey)] (from its verified log)."""
        return list(self.registry.verified_state(did).history)

    def invalidate(self, did: str) -> None:
        now = time.time()
        with self._lock:
            if now - self._forced.get(did, float("-inf")) < self.min_refresh_interval:
                return  # refreshed very recently; keep the cached answer
            self._forced[did] = now
            if len(self._forced) > self.max_entries:
                self._forced = {k: v for k, v in self._forced.items() if now - v < self.min_refresh_interval}
            self._cache.pop(did, None)

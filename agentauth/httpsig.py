"""Proof-of-possession request signing for agents.

Every request an agent makes carries

    Authorization: AgentSig did="did:agent:…",kid="did:agent:…#key-N",aud="api.example.com",
                   ts="1790000000",nonce="…",sig="…"

where `sig` is an Ed25519 signature over:

    agentauth-request/1
    <METHOD>
    <audience, i.e. the host the request is meant for>
    <path?query>
    <ts>
    <nonce>
    <digest of body>
    <digest of the AgentGrant header, or of "" when absent>

Binding the audience stops a request captured by one service being replayed
against another; the timestamp window + nonce cache stop replay against the
same service. Covering the AgentGrant header means the agent explicitly asserts
*which* authority it is acting under for this exact request. No bearer secret
ever crosses the wire.
"""

from __future__ import annotations

import logging
import re
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable
from urllib.parse import urlsplit

from .crypto import Signer, digest, verify
from .identity import is_agent_did

SCHEME = "AgentSig"
DEFAULT_MAX_SKEW = 120  # seconds
MAX_HEADER_BYTES = 4096
REQUIRED_PARAMS = ("did", "kid", "aud", "ts", "nonce", "sig")

_PARAM_RE = re.compile(r'\s*([A-Za-z0-9_]+)="([^"]*)"\s*(?:,|\Z)')
_TS_RE = re.compile(r"\A[0-9]{1,15}\Z")
# >= 16 characters (the reference client sends 22 base64url characters = 128 bits).
_NONCE_RE = re.compile(r"\A[A-Za-z0-9_\-.~+/=]{16,128}\Z")
_KID_RE = re.compile(r"\A(.+)#key-(0|[1-9][0-9]{0,8})\Z")
_AUD_RE = re.compile(r"\A[\x21\x23-\x2b\x2d-\x7e]{1,255}\Z")  # ASCII host[:port], see grants._AUD_RE

log = logging.getLogger("agentauth.httpsig")


class AuthError(Exception):
    def __init__(self, message: str, status: int = 401):
        super().__init__(message)
        self.status = status


def signing_string(
    method: str, audience: str, path: str, ts: str, nonce: str, body: bytes, grants: str = ""
) -> bytes:
    return "\n".join(
        [
            "agentauth-request/1",
            method.upper(),
            audience.lower(),
            path,
            ts,
            nonce,
            digest(body or b""),
            digest((grants or "").encode()),
        ]
    ).encode()


def sign_request(
    *,
    did: str,
    kid: str,
    key: Signer,
    method: str,
    url: str,
    body: bytes = b"",
    ts: Optional[int] = None,
    nonce: Optional[str] = None,
    grants: str = "",
) -> str:
    """Return the value for the Authorization header."""
    parts = urlsplit(url)
    audience = parts.netloc
    if "@" in audience:
        raise ValueError("URLs with userinfo are not supported for signed requests")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    ts_s = str(int(ts if ts is not None else time.time()))
    nonce = nonce or secrets.token_urlsafe(16)
    sig = key.sign(signing_string(method, audience, path, ts_s, nonce, body, grants))
    params = {"did": did, "kid": kid, "aud": audience, "ts": ts_s, "nonce": nonce, "sig": sig}
    for k, v in params.items():
        if '"' in v or "\n" in v or "\r" in v:
            raise ValueError(f"{k} must not contain quotes or newlines")
    return SCHEME + " " + ",".join(f'{k}="{v}"' for k, v in params.items())


def parse_authorization(header: str) -> dict:
    """Strictly parse an AgentSig header. Duplicate or malformed parameters are rejected."""
    if not isinstance(header, str) or not header.startswith(SCHEME + " "):
        raise AuthError(f"missing or non-{SCHEME} Authorization header")
    if len(header.encode("utf-8", "surrogatepass")) > MAX_HEADER_BYTES:
        raise AuthError("Authorization header too large")
    rest = header[len(SCHEME) + 1 :]
    params: dict = {}
    pos = 0
    while pos < len(rest):
        m = _PARAM_RE.match(rest, pos)
        if not m or m.end() == pos:
            raise AuthError("malformed Authorization header")
        k, v = m.group(1), m.group(2)
        if k in params:
            raise AuthError(f"duplicate Authorization parameter {k!r}")
        params[k] = v
        pos = m.end()
    missing = set(REQUIRED_PARAMS) - params.keys()
    if missing:
        raise AuthError(f"Authorization header missing: {', '.join(sorted(missing))}")
    return params


def _kid_seq(kid: str) -> int:
    m = _KID_RE.match(kid) if isinstance(kid, str) else None
    return int(m.group(2)) if m else -1


# --------------------------------------------------------------------------- #
# Replay protection
# --------------------------------------------------------------------------- #


class ReplayCacheUnavailable(Exception):
    """The replay cache can't give a safe answer (backend down, or full). Fail closed."""


@runtime_checkable
class ReplayCache(Protocol):
    """Interface for nonce stores. `check_and_store` must be atomic across every
    process that verifies requests for the same audiences: return True the
    first time (did, nonce) is seen within the window, False afterwards.
    Raise `ReplayCacheUnavailable` (or any exception) when unsure; the request
    is then refused with 503."""

    def check_and_store(self, did: str, nonce: str) -> bool: ...


class NonceCache:
    """In-memory, single-process replay cache.

    Only safe when exactly one process verifies requests for an audience. For
    more than one replica or worker, use `agentauth.backends.redis.RedisNonceCache`.

    Entries all share one TTL, so insertion order is expiry order and pruning is
    O(1) amortized. When `max_entries` unexpired nonces are held, new requests
    are refused rather than evicting live entries (which would allow replays).
    """

    def __init__(self, ttl: int, max_entries: int = 1_000_000, max_per_did: int = 100_000):
        self.ttl = ttl
        self.max_entries = max_entries
        # One agent may not hold more than this many live nonces, so a single (valid,
        # signing) agent can't fill the cache and lock every other agent out.
        self.max_per_did = max_per_did
        self._seen: OrderedDict = OrderedDict()
        self._per_did: dict = {}
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        seen = self._seen
        while seen:
            k, exp = next(iter(seen.items()))
            if exp > now:
                break
            seen.popitem(last=False)
            left = self._per_did.get(k[0], 1) - 1
            if left:
                self._per_did[k[0]] = left
            else:
                self._per_did.pop(k[0], None)

    def check_and_store(self, did: str, nonce: str) -> bool:
        now = time.time()
        with self._lock:
            self._prune(now)
            key = (did, nonce)
            if key in self._seen:
                return False
            if len(self._seen) >= self.max_entries:
                raise ReplayCacheUnavailable("replay cache is full")
            if self._per_did.get(did, 0) >= self.max_per_did:
                raise ReplayCacheUnavailable("too many requests from this agent inside the replay window")
            self._seen[key] = now + self.ttl
            self._per_did[did] = self._per_did.get(did, 0) + 1
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)


@dataclass
class VerifiedAgent:
    did: str
    kid: str
    key: str
    audience: str = ""


# Given a DID, return (current multikey, current key id) — or None if unknown/inactive.
KeyResolver = Callable[[str], Optional[tuple]]


def resolve_or_fail(resolve_key: KeyResolver, did: str, error=AuthError) -> Optional[tuple]:
    """Call a key resolver, turning infrastructure failures into a 503 (fail closed)."""
    try:
        return resolve_key(did)
    except error:
        raise
    except Exception as e:  # registry down, equivocation detected, bad response, ...
        log.warning("key resolution failed for %s: %s", did, e)
        raise error(f"could not resolve {did}: {e}", 503) from None


class RequestVerifier:
    """Verifies signed agent requests. Usable by the registry or any relying party."""

    def __init__(
        self,
        resolve_key: KeyResolver,
        audiences: set,
        max_skew: int = DEFAULT_MAX_SKEW,
        nonce_cache: Optional[ReplayCache] = None,
        *,
        bind_host: bool = False,
    ):
        """`bind_host=True` additionally requires the signed audience to equal the Host the
        request arrived on (integrations pass it). Turn it on when one app serves several
        audiences and routes by Host; leave it off when a proxy rewrites Host."""
        if not audiences:
            raise ValueError("RequestVerifier needs at least one audience")
        if not 0 < max_skew <= 3600:
            raise ValueError("max_skew must be between 1 and 3600 seconds")
        self.resolve_key = resolve_key
        self.audiences = {a.lower() for a in audiences}
        self.max_skew = max_skew
        self.bind_host = bind_host
        # A request stamped max_skew in the future stays valid until 2*max_skew after we first
        # see it; the nonce must be remembered at least that long (+1 s for rounding).
        self.min_nonce_ttl = 2 * max_skew + 1
        if nonce_cache is None:
            nonce_cache = NonceCache(ttl=self.min_nonce_ttl)
        ttl = getattr(nonce_cache, "ttl", None)
        if isinstance(ttl, (int, float)) and ttl < self.min_nonce_ttl:
            raise ValueError(
                f"replay cache ttl ({ttl}s) is shorter than the replay window ({self.min_nonce_ttl}s "
                f"for max_skew={max_skew}); requests could be replayed after their nonce expires"
            )
        self.nonces = nonce_cache

    def verify(
        self, *, authorization: str, method: str, path: str, body: bytes, grants: str = "",
        host: Optional[str] = None,
    ) -> VerifiedAgent:
        p = parse_authorization(authorization)
        if not _AUD_RE.match(p["aud"]) or p["aud"].lower() not in self.audiences:
            raise AuthError(f"request was signed for a different audience ({p['aud'][:100]})")
        if self.bind_host and (host is None or host.lower() != p["aud"].lower()):
            raise AuthError("request was signed for a different host than the one it was sent to")
        if not _TS_RE.match(p["ts"]):
            raise AuthError("ts must be an integer number of seconds")
        if abs(time.time() - int(p["ts"])) > self.max_skew:
            raise AuthError("request timestamp outside allowed window")
        if not _NONCE_RE.match(p["nonce"]):
            raise AuthError("nonce must be 16-128 URL-safe characters")
        if not is_agent_did(p["did"]):
            raise AuthError("did is not a did:agent identifier")
        m = _KID_RE.match(p["kid"])
        if not m or m.group(1) != p["did"]:
            raise AuthError("kid must be '<did>#key-<n>'")

        resolved = resolve_or_fail(self.resolve_key, p["did"])
        if resolved is None:
            raise AuthError("unknown or deactivated agent")
        key, kid = resolved
        if p["kid"] != kid and _kid_seq(p["kid"]) > _kid_seq(kid) and hasattr(self.resolve_key, "invalidate"):
            # Caller claims a newer key than our cache holds: the agent probably
            # just rotated. Refresh once instead of rejecting for a whole TTL.
            # (Resolvers rate-limit forced refreshes, so this can't be used to
            # hammer the registry.)
            self.resolve_key.invalidate(p["did"])
            resolved = resolve_or_fail(self.resolve_key, p["did"])
            if resolved is None:
                raise AuthError("unknown or deactivated agent")
            key, kid = resolved
        if p["kid"] != kid:
            raise AuthError("signed with a key that is not the agent's current key")

        msg = signing_string(method, p["aud"], path, p["ts"], p["nonce"], body, grants)
        if not verify(key, msg, p["sig"]):
            raise AuthError("bad request signature")
        # Only burn the nonce once the signature checks out, so garbage can't fill the cache.
        try:
            fresh = self.nonces.check_and_store(p["did"], p["nonce"])
        except Exception as e:
            log.error("replay cache failure: %s", e)
            raise AuthError("replay protection unavailable", 503) from None
        if not fresh:
            raise AuthError("replayed request (nonce already used)")
        return VerifiedAgent(did=p["did"], kid=kid, key=key, audience=p["aud"].lower())

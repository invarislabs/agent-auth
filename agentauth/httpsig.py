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

import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urlsplit

from .crypto import KeyPair, digest, verify

SCHEME = "AgentSig"
DEFAULT_MAX_SKEW = 120  # seconds

_PARAM_RE = re.compile(r'(\w+)="([^"]*)"')


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
    key: KeyPair,
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
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    ts_s = str(int(ts if ts is not None else time.time()))
    nonce = nonce or secrets.token_urlsafe(16)
    sig = key.sign(signing_string(method, audience, path, ts_s, nonce, body, grants))
    params = {"did": did, "kid": kid, "aud": audience, "ts": ts_s, "nonce": nonce, "sig": sig}
    return SCHEME + " " + ",".join(f'{k}="{v}"' for k, v in params.items())


def parse_authorization(header: str) -> dict:
    if not header or not header.startswith(SCHEME + " "):
        raise AuthError(f"missing or non-{SCHEME} Authorization header")
    params = dict(_PARAM_RE.findall(header[len(SCHEME) + 1 :]))
    missing = {"did", "kid", "aud", "ts", "nonce", "sig"} - params.keys()
    if missing:
        raise AuthError(f"Authorization header missing: {', '.join(sorted(missing))}")
    return params


def _kid_seq(kid: str) -> int:
    try:
        return int(kid.rsplit("#key-", 1)[1])
    except (IndexError, ValueError):
        return -1


class NonceCache:
    """In-memory replay cache. Swap for Redis/memcached when running >1 replica."""

    def __init__(self, ttl: int):
        self.ttl = ttl
        self._seen: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def check_and_store(self, did: str, nonce: str) -> bool:
        now = time.time()
        with self._lock:
            if len(self._seen) > 10_000:
                self._seen = {k: exp for k, exp in self._seen.items() if exp > now}
            key = (did, nonce)
            if key in self._seen and self._seen[key] > now:
                return False
            self._seen[key] = now + self.ttl
            return True


@dataclass
class VerifiedAgent:
    did: str
    kid: str
    key: str
    audience: str = ""


# Given a DID, return (current multikey, current key id) — or None if unknown/inactive.
KeyResolver = Callable[[str], Optional[tuple]]


class RequestVerifier:
    """Verifies signed agent requests. Usable by the registry or any relying party."""

    def __init__(
        self,
        resolve_key: KeyResolver,
        audiences: set,
        max_skew: int = DEFAULT_MAX_SKEW,
        nonce_cache: Optional[NonceCache] = None,
    ):
        self.resolve_key = resolve_key
        self.audiences = {a.lower() for a in audiences}
        self.max_skew = max_skew
        self.nonces = nonce_cache or NonceCache(ttl=2 * max_skew)

    def verify(
        self, *, authorization: str, method: str, path: str, body: bytes, grants: str = ""
    ) -> VerifiedAgent:
        p = parse_authorization(authorization)
        if p["aud"].lower() not in self.audiences:
            raise AuthError(f"request was signed for a different audience ({p['aud']})")
        try:
            ts = int(p["ts"])
        except ValueError:
            raise AuthError("ts must be an integer") from None
        if abs(time.time() - ts) > self.max_skew:
            raise AuthError("request timestamp outside allowed window")

        resolved = self.resolve_key(p["did"])
        if resolved is None:
            raise AuthError("unknown or deactivated agent")
        key, kid = resolved
        if p["kid"] != kid and _kid_seq(p["kid"]) > _kid_seq(kid) and hasattr(self.resolve_key, "invalidate"):
            # Caller claims a newer key than our cache holds: the agent probably
            # just rotated. Refresh once instead of rejecting for a whole TTL.
            self.resolve_key.invalidate(p["did"])
            resolved = self.resolve_key(p["did"])
            if resolved is None:
                raise AuthError("unknown or deactivated agent")
            key, kid = resolved
        if p["kid"] != kid:
            raise AuthError("signed with a key that is not the agent's current key")

        msg = signing_string(method, p["aud"], path, p["ts"], p["nonce"], body, grants)
        if not verify(key, msg, p["sig"]):
            raise AuthError("bad request signature")
        # Only burn the nonce once the signature checks out, so garbage can't fill the cache.
        if not self.nonces.check_and_store(p["did"], p["nonce"]):
            raise AuthError("replayed request (nonce already used)")
        return VerifiedAgent(did=p["did"], kid=kid, key=key, audience=p["aud"].lower())

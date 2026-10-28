"""Capability grants and delegation chains.

A *grant* is a small signed statement:

    "<iss> lets <sub> do <scopes> at <aud> until <exp>, and <sub> may re-delegate <depth> more times."

Grants chain. A human or org (the *principal*) issues a root grant to an agent.
That agent can issue a narrower child grant to a sub-agent, and so on. Each
link must:

* be signed by the current key of its issuer
* be issued by the subject of the link before it
* point at its parent by id
* only **attenuate**: scopes ⊆ parent, audiences ⊆ parent, validity window
  inside the parent's, and delegation depth strictly smaller

A relying service accepts a chain when every link checks out, the leaf's subject
is the agent that signed the request, the root issuer is a principal the
service trusts for those scopes, no identity in the chain is deactivated, and no
grant in the chain has been revoked. Deactivating or revoking anything upstream
therefore cuts off everything downstream.

Wire format (HTTP header ``AgentGrant``): links joined with ``,``, root first;
each link is ``b64url(canonical_json(body)) "." b64url(signature)``.
"""

from __future__ import annotations

import inspect
import json
import logging
import re
import secrets
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Optional

from .crypto import MAX_SAFE_INT, Signer, b64u, b64u_decode, canonical_json, verify
from .httpsig import _kid_seq
from .identity import is_agent_did
from .limits import LimitError, Limits, UsageLedger

log = logging.getLogger("agentauth.grants")

VERSION = "agentauth-grant/1"
REVOCATION_VERSION = "agentauth-revocation/1"
HEADER = "AgentGrant"
DEFAULT_TTL = 15 * 60
MAX_TTL = 24 * 60 * 60
MAX_CHAIN = 8
CLOCK_SKEW = 60
MAX_HEADER_BYTES = 32 * 1024
MAX_SCOPES = 64
MAX_AUDIENCES = 32
MAX_ID_LEN = 128

_GRANT_FIELDS = {"v", "id", "iss", "kid", "sub", "scope", "aud", "nbf", "exp", "depth", "parent"}
_OPTIONAL_GRANT_FIELDS = {"limits"}
_REVOCATION_FIELDS = {"v", "grant", "iss", "ts"}
_ID_RE = re.compile(r"\A[A-Za-z0-9_\-.:]{1,128}\Z")
# host[:port]: printable ASCII without space, '"' or ','. ASCII-only keeps case-insensitive
# comparison identical in every language (no Unicode case folding).
_AUD_RE = re.compile(r"\A[\x21\x23-\x2b\x2d-\x7e]{1,255}\Z")
_SCOPE_CHARS_RE = re.compile(r"\A[\x21-\x7e]{1,128}\Z")
MAX_GRANT_DEPTH = 8  # JSON nesting of a grant body (limits -> spend -> value is depth 3)


class GrantError(Exception):
    def __init__(self, message: str, status: int = 403):
        super().__init__(message)
        self.status = status


# --------------------------------------------------------------------------- #
# Scopes
#
#   "tools.search"  exact action
#   "files.*"       any action under "files."
#   "*"             everything (only sensible for a root grant)
# --------------------------------------------------------------------------- #


def _valid_scope(s: str) -> bool:
    if not isinstance(s, str) or not _SCOPE_CHARS_RE.match(s):
        return False
    return s == "*" or "*" not in s[:-1] and (not s.endswith("*") or s.endswith(".*"))


def scope_covers(parent: str, child: str) -> bool:
    """Does `parent` include everything `child` allows?"""
    if parent == "*" or parent == child:
        return True
    if parent.endswith(".*"):
        prefix = parent[:-1]  # keep the trailing dot
        return child.startswith(prefix) and child != prefix
    return False


def scopes_cover(parents: Iterable[str], children: Iterable[str]) -> bool:
    parents = list(parents)
    return all(any(scope_covers(p, c) for p in parents) for c in children)


def _valid_audience(a: Any) -> bool:
    return isinstance(a, str) and _AUD_RE.match(a) is not None


def _ascii_lower(s: str) -> str:
    return s.translate(_ASCII_LOWER)


_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def audience_covers(parents: Iterable[str], children: Iterable[str]) -> bool:
    parents = {_ascii_lower(p) for p in parents}
    return "*" in parents or all(_ascii_lower(c) in parents for c in children)


# --------------------------------------------------------------------------- #
# Grant objects
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Grant:
    body: dict
    sig: str

    # convenient accessors
    id = property(lambda self: self.body["id"])
    iss = property(lambda self: self.body["iss"])
    sub = property(lambda self: self.body["sub"])
    scopes = property(lambda self: list(self.body["scope"]))
    aud = property(lambda self: list(self.body["aud"]))
    exp = property(lambda self: self.body["exp"])
    nbf = property(lambda self: self.body["nbf"])
    depth = property(lambda self: self.body["depth"])
    parent = property(lambda self: self.body["parent"])

    @property
    def limits(self) -> Limits:
        return Limits.from_dict(self.body.get("limits"))

    def encode(self) -> str:
        return b64u(canonical_json(self.body)) + "." + self.sig

    @classmethod
    def decode(cls, token: str) -> Grant:
        """Parse one link. The payload must be exactly canonical_json(body) (protocol §4.2):
        no duplicate keys, no floats, no alternative encodings that different parsers
        could read differently."""
        try:
            b, s = token.strip().split(".")
            raw = b64u_decode(b)
            body = json.loads(raw, parse_constant=_reject_constant, object_pairs_hook=_no_duplicate_keys)
        except (ValueError, TypeError, RecursionError):
            raise GrantError("malformed grant", 400) from None
        if not isinstance(body, dict) or not _shape_ok(body, MAX_GRANT_DEPTH):
            raise GrantError("malformed grant", 400)
        try:
            canonical = canonical_json(body)
        except (TypeError, ValueError):
            raise GrantError("malformed grant: not canonical JSON (floats are not allowed)", 400) from None
        if canonical != raw:
            raise GrantError("malformed grant: payload is not canonical JSON", 400)
        return cls(body, s)


def _reject_constant(name: str):
    raise ValueError(f"{name} is not valid JSON")


def _no_duplicate_keys(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r}")
        d[k] = v
    return d


def _shape_ok(obj: Any, limit: int) -> bool:
    stack = [(obj, 1)]
    while stack:
        o, d = stack.pop()
        if isinstance(o, (dict, list)):
            if d > limit:
                return False
            stack.extend((v, d + 1) for v in (o.values() if isinstance(o, dict) else o))
        elif isinstance(o, int) and not isinstance(o, bool) and not -MAX_SAFE_INT <= o <= MAX_SAFE_INT:
            return False
    return True


@dataclass
class GrantChain:
    links: list = field(default_factory=list)

    @property
    def root(self) -> Grant:
        return self.links[0]

    @property
    def leaf(self) -> Grant:
        return self.links[-1]

    def encode(self) -> str:
        return ",".join(g.encode() for g in self.links)

    @classmethod
    def decode(cls, header: str) -> GrantChain:
        if header and len(header) > MAX_HEADER_BYTES:
            raise GrantError(f"{HEADER} header larger than {MAX_HEADER_BYTES} bytes", 400)
        parts = [p for p in (header or "").split(",") if p.strip()]
        if not parts:
            raise GrantError("no grant presented", 401)
        if len(parts) > MAX_CHAIN:
            raise GrantError(f"delegation chain longer than {MAX_CHAIN}")
        return cls([Grant.decode(p) for p in parts])

    def describe(self) -> list:
        return [
            {"id": g.id, "iss": g.iss, "sub": g.sub, "scope": g.scopes, "aud": g.aud,
             "nbf": g.nbf, "exp": g.exp, "depth": g.depth, "parent": g.parent,
             "limits": g.body.get("limits")}
            for g in self.links
        ]


def new_grant_id() -> str:
    """A random grant id (128 bits, base64url) that never starts with "-".

    Any id matching the protocol's format is valid; avoiding a leading "-"
    just keeps ids usable as command-line arguments (`agentauth revoke`)
    without a `--` separator.
    """
    while True:
        gid = secrets.token_urlsafe(16)
        if not gid.startswith("-"):
            return gid


def issue(
    *,
    issuer_did: str,
    issuer_kid: str,
    issuer_key: Signer,
    subject: str,
    scopes: list,
    audiences: list,
    ttl: int = DEFAULT_TTL,
    depth: int = 0,
    parent: Optional[GrantChain] = None,
    limits: Optional[Limits] = None,
    now: Optional[int] = None,
) -> GrantChain:
    """Issue a grant, as a new root or as a delegation beneath `parent`.

    Checks attenuation locally so mistakes surface at issue time, not at the
    relying party. Returns the full chain to hand to the subject.
    """
    now = int(now if now is not None else time.time())
    if not 0 < ttl <= MAX_TTL:
        raise GrantError(f"ttl must be between 1 and {MAX_TTL} seconds", 400)
    if not scopes or len(scopes) > MAX_SCOPES or not all(_valid_scope(s) for s in scopes):
        raise GrantError(f"invalid scopes: {scopes}", 400)
    if not audiences or len(audiences) > MAX_AUDIENCES or not all(map(_valid_audience, audiences)):
        raise GrantError("1-32 audiences (ASCII host[:port], no whitespace or commas) are required", 400)
    if not isinstance(depth, int) or isinstance(depth, bool) or not 0 <= depth <= MAX_CHAIN:
        raise GrantError(f"depth must be an integer between 0 and {MAX_CHAIN}", 400)
    if not is_agent_did(subject):
        raise GrantError("subject must be a did:agent identifier", 400)
    if subject == issuer_did:
        raise GrantError("cannot issue a grant to yourself", 400)

    limits = limits or Limits()
    nbf, exp = now, now + ttl
    links: list = []
    parent_id = None
    if parent is not None:
        p = parent.leaf
        if p.sub != issuer_did:
            raise GrantError("you can only delegate a grant that was issued to you", 400)
        if p.depth < 1:
            raise GrantError("parent grant does not allow further delegation", 400)
        if not scopes_cover(p.scopes, scopes):
            raise GrantError("delegated scopes exceed the parent grant", 400)
        if not audience_covers(p.aud, audiences):
            raise GrantError("delegated audiences exceed the parent grant", 400)
        exp = min(exp, p.exp)
        nbf = max(nbf, p.nbf)
        depth = min(depth, p.depth - 1)
        if exp <= nbf:
            raise GrantError("parent grant has expired", 400)
        try:
            parent_limits = p.limits
        except LimitError as e:
            raise GrantError(f"parent grant has invalid limits: {e}", 400) from None
        limits = parent_limits.inherit_into(limits)
        why = parent_limits.narrowing_violation(limits)
        if why:
            raise GrantError(f"delegated limits exceed the parent grant: {why}", 400)
        links, parent_id = list(parent.links), p.id

    if limits.stateful and "*" in {_ascii_lower(a) for a in audiences}:
        raise GrantError("budget, rate and use limits can't apply to audience '*': every service would "
                         "count them separately; list the audiences explicitly", 400)
    body = {
        "v": VERSION,
        "id": new_grant_id(),
        "iss": issuer_did,
        "kid": issuer_kid,
        "sub": subject,
        "scope": sorted(set(scopes)),
        "aud": sorted({_ascii_lower(a) for a in audiences}),
        "nbf": nbf,
        "exp": exp,
        "depth": depth,
        "parent": parent_id,
    }
    if not limits.empty:
        body["limits"] = limits.to_dict()
    links.append(Grant(body, issuer_key.sign(canonical_json(body))))
    return GrantChain(links)


def make_revocation(*, issuer_did: str, issuer_key: Signer, grant_id: str) -> dict:
    if not isinstance(grant_id, str) or not _ID_RE.match(grant_id):
        raise GrantError("grant id must be 1-128 URL-safe characters", 400)
    body = {"v": REVOCATION_VERSION, "grant": grant_id, "iss": issuer_did, "ts": int(time.time())}
    return {"body": body, "sig": issuer_key.sign(canonical_json(body))}


def parse_revocation(event: Any) -> dict:
    """Structural checks on a revocation (no signature check). Returns its body."""
    body = event.get("body") if isinstance(event, dict) else None
    if not isinstance(body, dict) or body.get("v") != REVOCATION_VERSION or set(body) != _REVOCATION_FIELDS:
        raise GrantError("malformed revocation", 400)
    if set(event) - {"body", "sig"} or not isinstance(event.get("sig"), str):
        raise GrantError("malformed revocation", 400)
    if not isinstance(body["grant"], str) or not _ID_RE.match(body["grant"]) or not is_agent_did(body["iss"]):
        raise GrantError("malformed revocation", 400)
    ts = body["ts"]
    if not isinstance(ts, int) or isinstance(ts, bool) or not 0 <= ts <= MAX_SAFE_INT:
        raise GrantError("malformed revocation", 400)
    return body


def verify_revocation(event: dict, issuer_key: str) -> dict:
    """Check a revocation's structure and that `issuer_key` signed it."""
    body = parse_revocation(event)
    try:
        msg = canonical_json(body)
    except (TypeError, ValueError):
        raise GrantError("malformed revocation", 400) from None
    if not verify(issuer_key, msg, event["sig"]):
        raise GrantError("bad revocation signature", 400)
    return body


# --------------------------------------------------------------------------- #
# Verification (relying party)
# --------------------------------------------------------------------------- #

# did -> (current multikey, current kid) or None
KeyResolver = Callable[[str], Optional[tuple]]
# (principal did, audience) -> scopes that principal may grant here, or None if untrusted
RootPolicy = Callable[[str, str], Optional[Iterable[str]]]
# [(issuer did, grant id), ...] -> set of the pairs that are revoked.
# Revocations are keyed by issuer so nobody can revoke someone else's grant.
RevocationCheck = Callable[[list], set]


def trust_principals(policy: dict) -> RootPolicy:
    """Simple RootPolicy from a dict: {principal_did: ["scope", ...]}."""
    return lambda did, aud: policy.get(did)


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def check_grant_body(b: dict, i: int = 0) -> None:
    """Structural validation of one grant body. Unknown fields are rejected (fail closed)."""
    keys = set(b)
    if b.get("v") != VERSION:
        raise GrantError(f"link {i}: unsupported grant version")
    if not _GRANT_FIELDS <= keys or keys - _GRANT_FIELDS - _OPTIONAL_GRANT_FIELDS:
        unknown = sorted(keys - _GRANT_FIELDS - _OPTIONAL_GRANT_FIELDS)
        raise GrantError(f"link {i}: missing or unknown fields" + (f" ({', '.join(unknown)})" if unknown else ""))
    for k, t in (("id", str), ("iss", str), ("kid", str), ("sub", str), ("scope", list),
                 ("aud", list), ("nbf", int), ("exp", int), ("depth", int)):
        if not isinstance(b.get(k), t) or isinstance(b.get(k), bool):
            raise GrantError(f"link {i}: missing or bad field {k!r}")
    if not _ID_RE.match(b["id"]):
        raise GrantError(f"link {i}: bad grant id")
    if not is_agent_did(b["iss"]) or not is_agent_did(b["sub"]):
        raise GrantError(f"link {i}: iss and sub must be did:agent identifiers")
    if not b["kid"].startswith(b["iss"] + "#key-") or _kid_seq(b["kid"]) < 0:
        raise GrantError(f"link {i}: kid does not belong to the issuer")
    if not b["scope"] or len(b["scope"]) > MAX_SCOPES or not all(_valid_scope(s) for s in b["scope"]):
        raise GrantError(f"link {i}: invalid scope")
    if not b["aud"] or len(b["aud"]) > MAX_AUDIENCES or not all(map(_valid_audience, b["aud"])):
        raise GrantError(f"link {i}: invalid audience")
    if b["aud"] != sorted({_ascii_lower(a) for a in b["aud"]}) or b["scope"] != sorted(set(b["scope"])):
        raise GrantError(f"link {i}: aud must be lower-case, and aud and scope sorted without duplicates")
    if not (0 <= b["nbf"] <= MAX_SAFE_INT and 0 <= b["exp"] <= MAX_SAFE_INT):
        raise GrantError(f"link {i}: nbf/exp out of range")
    if not 0 <= b["depth"] <= MAX_SAFE_INT:
        raise GrantError(f"link {i}: depth out of range")
    if b["parent"] is not None and not (isinstance(b["parent"], str) and _ID_RE.match(b["parent"])):
        raise GrantError(f"link {i}: bad parent id")
    if "limits" in b and not isinstance(b["limits"], dict):
        raise GrantError(f"link {i}: limits must be an object")


@dataclass
class AuthorizedAgent:
    did: str
    principal: str  # the root issuer (human / org) the authority traces back to
    scopes: list  # effective scopes = the leaf grant's scopes
    chain: GrantChain
    via: list  # DIDs from principal to agent, e.g. [human, agent, sub-agent]
    link_limits: list = field(default_factory=list)  # [((iss, grant id), Limits)] root → leaf
    ledger: Optional[UsageLedger] = None
    charged: int = 0  # amount charged for this request (see GrantVerifier.enforce)
    link_expiry: dict = field(default_factory=dict)  # (iss, grant id) -> exp
    _refund_lock: Any = field(default_factory=threading.Lock, repr=False, compare=False)

    def allows(self, scope: str) -> bool:
        return any(scope_covers(s, scope) for s in self.scopes)

    @property
    def grant_ids(self) -> list:
        return [g.id for g in self.chain.links]

    @property
    def limits(self) -> Optional[dict]:
        """The leaf grant's limits (which already include everything inherited)."""
        return self.chain.leaf.body.get("limits")

    def refund(self, amount: Optional[int] = None) -> None:
        """Return spend to every budget in the chain, e.g. when the paid action failed.

        You can only give back what this request was charged: refunding more
        would let a service bug (or a malicious caller-controlled amount) mint
        budget out of nothing.
        """
        with self._refund_lock:
            amount = self.charged if amount is None else amount
            if not _is_int(amount) or amount < 0:
                raise GrantError("refund amount must be a non-negative integer", 400)
            if amount > self.charged:
                raise GrantError(f"cannot refund {amount}: only {self.charged} was charged", 400)
            if self.ledger is not None and amount:
                self.ledger.refund([x for x in self.link_limits if x[1].stateful], amount)
                self.charged -= amount


def _accepts_kwarg(fn: Callable, name: str) -> bool:
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    return name in params or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


class GrantVerifier:
    def __init__(
        self,
        resolve_key: KeyResolver,
        root_policy: RootPolicy,
        revoked: Optional[RevocationCheck] = None,
        max_chain: int = MAX_CHAIN,
        ledger: Optional[UsageLedger] = None,
    ):
        if revoked is None:
            log.warning("GrantVerifier created without a revocation check: revoked grants will be accepted "
                        "(pass revoked=RegistryRevocationChecker(...))")
        self.ledger = ledger if ledger is not None else UsageLedger()
        self.resolve_key = resolve_key
        self.root_policy = root_policy
        self.revoked = revoked or (lambda ids: set())
        self.max_chain = min(max_chain, MAX_CHAIN)
        # Ledgers written for v0.3 don't take `expires_at`; keep supporting them.
        self._ledger_takes_expiry = _accepts_kwarg(self.ledger.consume, "expires_at")

    def _resolve(self, did: str) -> Optional[tuple]:
        try:
            return self.resolve_key(did)
        except GrantError:
            raise
        except Exception as e:
            log.warning("issuer key resolution failed for %s: %s", did, e)
            raise GrantError(f"could not resolve grant issuer {did}: {e}", 503) from None

    def _issuer_key(self, did: str, kid: str) -> str:
        found = self._resolve(did)
        if found and _kid_seq(kid) > _kid_seq(found[1]) and hasattr(self.resolve_key, "invalidate"):
            # grant claims a newer key than cached: issuer probably just rotated
            self.resolve_key.invalidate(did)
            found = self._resolve(did)
        if found is None:
            raise GrantError(f"grant issuer {did} is unknown or deactivated")
        key, current_kid = found
        if kid != current_kid:
            raise GrantError(f"grant was signed with a key {did} no longer uses; re-issue it")
        return key

    def verify(self, header: str, *, requester: str, audience: str, now: Optional[int] = None) -> AuthorizedAgent:
        chain = GrantChain.decode(header)
        if len(chain.links) > self.max_chain:
            raise GrantError(f"delegation chain longer than {self.max_chain}")
        now = int(now if now is not None else time.time())
        audience = _ascii_lower(audience)

        prev: Optional[Grant] = None
        prev_limits = Limits()
        link_limits: list = []
        seen_ids: set = set()
        for i, g in enumerate(chain.links):
            b = g.body
            check_grant_body(b, i)
            if (g.iss, g.id) in seen_ids:
                raise GrantError(f"link {i}: grant appears twice in the chain")
            seen_ids.add((g.iss, g.id))
            if g.iss == g.sub:
                raise GrantError(f"link {i}: a grant cannot be issued to its own issuer")
            if not (g.nbf - CLOCK_SKEW <= now < g.exp + CLOCK_SKEW) or not 0 < g.exp - g.nbf <= MAX_TTL:
                raise GrantError(f"link {i}: grant expired or not yet valid")
            if not audience_covers(g.aud, [audience]):
                raise GrantError(f"link {i}: grant is not valid for audience {audience}")
            try:
                lim = g.limits
            except LimitError as e:
                raise GrantError(f"link {i}: {e}") from None
            if lim.stateful and "*" in g.aud:
                raise GrantError(f"link {i}: budget, rate and use limits can't apply to audience '*'")

            if prev is None:
                if g.parent is not None:
                    raise GrantError("chain is missing its root grant")
            else:
                if g.parent != prev.id or g.iss != prev.sub:
                    raise GrantError(f"link {i}: does not chain to its parent")
                if prev.depth < 1 or g.depth > prev.depth - 1:
                    raise GrantError(f"link {i}: delegation depth exceeded")
                if not scopes_cover(prev.scopes, g.scopes) or not audience_covers(prev.aud, g.aud):
                    raise GrantError(f"link {i}: widens its parent's authority")
                if g.nbf < prev.nbf or g.exp > prev.exp:
                    raise GrantError(f"link {i}: outlives its parent")
                why = prev_limits.narrowing_violation(lim)
                if why:
                    raise GrantError(f"link {i}: loosens its parent's limits ({why})")

            key = self._issuer_key(g.iss, b["kid"])
            try:
                msg = canonical_json(b)
            except (TypeError, ValueError):
                raise GrantError(f"link {i}: grant is not canonicalizable") from None
            if not verify(key, msg, g.sig):
                raise GrantError(f"link {i}: bad signature")
            prev, prev_limits = g, lim
            link_limits.append(((g.iss, g.id), lim))

        if chain.leaf.sub != requester:
            raise GrantError("grant was issued to a different agent")

        try:
            allowed = self.root_policy(chain.root.iss, audience)
        except Exception as e:
            log.error("root policy failed for %s: %s", chain.root.iss, e)
            raise GrantError("root policy unavailable", 503) from None
        if allowed is None:
            raise GrantError("root issuer is not a principal this service trusts")
        if not scopes_cover(allowed, chain.root.scopes):
            raise GrantError("root grant exceeds what its principal may authorize here")

        try:
            revoked = self.revoked([(g.iss, g.id) for g in chain.links])
        except Exception as e:
            log.error("revocation check failed: %s", e)
            raise GrantError("revocation status unavailable", 503) from None
        if revoked:
            raise GrantError("a grant in the chain has been revoked")

        return AuthorizedAgent(
            did=requester,
            principal=chain.root.iss,
            scopes=chain.leaf.scopes,
            chain=chain,
            via=[chain.root.iss] + [g.sub for g in chain.links],
            link_limits=link_limits,
            ledger=self.ledger,
            link_expiry={(g.iss, g.id): g.exp + CLOCK_SKEW for g in chain.links},
        )

    def enforce(
        self,
        authz: AuthorizedAgent,
        *,
        resource: Optional[str] = None,
        amount: int = 0,
        unit: Optional[str] = None,
        now: Optional[float] = None,
    ) -> None:
        """Apply every link's limits to one concrete call, then record it.

        `resource` is what the call touches (a path, repo, account…). `amount`
        is what it costs, in `unit`. Stateless limits are checked on every link.
        Stateful ones (budget, rate, uses) are charged atomically against every
        link, so a parent's budget is shared by everything delegated under it.
        Ledger failures fail closed (503).
        """
        if not _is_int(amount) or not 0 <= amount <= MAX_SAFE_INT:
            raise GrantError("amount must be a non-negative integer", 400)
        try:
            for _, lim in authz.link_limits:
                lim.check_call(resource=resource, amount=amount, unit=unit)
            stateful = [x for x in authz.link_limits if x[1].stateful]
            if stateful:
                charge = amount if any(lim.total is not None for _, lim in stateful) else 0
                kw = {}
                if self._ledger_takes_expiry:
                    kw["expires_at"] = {k: authz.link_expiry.get(k) for k, _ in stateful}
                self.ledger.consume(stateful, charge, now, **kw)
                authz.charged += charge
        except LimitError as e:
            raise GrantError(str(e), e.status) from None
        except GrantError:
            raise
        except Exception as e:
            log.error("usage ledger failure: %s", e)
            raise GrantError("usage ledger unavailable", 503) from None

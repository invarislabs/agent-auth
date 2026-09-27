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

import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from .crypto import KeyPair, b64u, b64u_decode, canonical_json, verify
from .httpsig import _kid_seq
from .limits import LimitError, Limits, UsageLedger

VERSION = "agentauth-grant/1"
REVOCATION_VERSION = "agentauth-revocation/1"
HEADER = "AgentGrant"
DEFAULT_TTL = 15 * 60
MAX_TTL = 24 * 60 * 60
MAX_CHAIN = 8
CLOCK_SKEW = 60


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
    if not isinstance(s, str) or not s or len(s) > 128 or any(c.isspace() for c in s):
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


def audience_covers(parents: Iterable[str], children: Iterable[str]) -> bool:
    parents = {p.lower() for p in parents}
    return "*" in parents or all(c.lower() in parents for c in children)


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
    def decode(cls, token: str) -> "Grant":
        try:
            b, s = token.strip().split(".")
            body = json.loads(b64u_decode(b))
        except (ValueError, TypeError):
            raise GrantError("malformed grant", 400) from None
        if not isinstance(body, dict):
            raise GrantError("malformed grant", 400)
        return cls(body, s)


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
    def decode(cls, header: str) -> "GrantChain":
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


def issue(
    *,
    issuer_did: str,
    issuer_kid: str,
    issuer_key: KeyPair,
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
    if not scopes or not all(_valid_scope(s) for s in scopes):
        raise GrantError(f"invalid scopes: {scopes}", 400)
    if not audiences:
        raise GrantError("at least one audience is required", 400)
    if not isinstance(depth, int) or depth < 0:
        raise GrantError("depth must be a non-negative integer", 400)
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

    body = {
        "v": VERSION,
        "id": secrets.token_urlsafe(16),
        "iss": issuer_did,
        "kid": issuer_kid,
        "sub": subject,
        "scope": sorted(set(scopes)),
        "aud": sorted({a.lower() for a in audiences}),
        "nbf": nbf,
        "exp": exp,
        "depth": depth,
        "parent": parent_id,
    }
    if not limits.empty:
        body["limits"] = limits.to_dict()
    links.append(Grant(body, issuer_key.sign(canonical_json(body))))
    return GrantChain(links)


def make_revocation(*, issuer_did: str, issuer_key: KeyPair, grant_id: str) -> dict:
    body = {"v": REVOCATION_VERSION, "grant": grant_id, "iss": issuer_did, "ts": int(time.time())}
    return {"body": body, "sig": issuer_key.sign(canonical_json(body))}


def verify_revocation(event: dict, issuer_key: str) -> dict:
    body = event.get("body") if isinstance(event, dict) else None
    if not isinstance(body, dict) or body.get("v") != REVOCATION_VERSION:
        raise GrantError("malformed revocation", 400)
    if not isinstance(body.get("grant"), str) or not isinstance(body.get("iss"), str):
        raise GrantError("malformed revocation", 400)
    if not verify(issuer_key, canonical_json(body), event.get("sig") or ""):
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

    def allows(self, scope: str) -> bool:
        return any(scope_covers(s, scope) for s in self.scopes)

    @property
    def limits(self) -> Optional[dict]:
        """The leaf grant's limits (which already include everything inherited)."""
        return self.chain.leaf.body.get("limits")

    def refund(self, amount: Optional[int] = None) -> None:
        """Return spend to every budget in the chain, e.g. when the paid action failed."""
        amount = self.charged if amount is None else amount
        if self.ledger is not None and amount:
            self.ledger.refund([x for x in self.link_limits if x[1].stateful], amount)
            self.charged -= amount


class GrantVerifier:
    def __init__(
        self,
        resolve_key: KeyResolver,
        root_policy: RootPolicy,
        revoked: Optional[RevocationCheck] = None,
        max_chain: int = MAX_CHAIN,
        ledger: Optional[UsageLedger] = None,
    ):
        self.ledger = ledger or UsageLedger()
        self.resolve_key = resolve_key
        self.root_policy = root_policy
        self.revoked = revoked or (lambda ids: set())
        self.max_chain = max_chain

    def _issuer_key(self, did: str, kid: str) -> str:
        found = self.resolve_key(did)
        if found and _kid_seq(kid) > _kid_seq(found[1]) and hasattr(self.resolve_key, "invalidate"):
            # grant claims a newer key than cached: issuer probably just rotated
            self.resolve_key.invalidate(did)
            found = self.resolve_key(did)
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
        audience = audience.lower()

        prev: Optional[Grant] = None
        prev_limits: Optional[Limits] = None
        link_limits: list = []
        for i, g in enumerate(chain.links):
            b = g.body
            if b.get("v") != VERSION:
                raise GrantError(f"link {i}: unsupported grant version")
            for k, t in (("id", str), ("iss", str), ("kid", str), ("sub", str), ("scope", list),
                         ("aud", list), ("nbf", int), ("exp", int), ("depth", int)):
                if not isinstance(b.get(k), t) or isinstance(b.get(k), bool):
                    raise GrantError(f"link {i}: missing or bad field {k!r}")
            if not g.scopes or not all(_valid_scope(s) for s in g.scopes):
                raise GrantError(f"link {i}: invalid scope")
            if not (g.nbf - CLOCK_SKEW <= now < g.exp + CLOCK_SKEW) or g.exp - g.nbf > MAX_TTL:
                raise GrantError(f"link {i}: grant expired or not yet valid")
            if not audience_covers(g.aud, [audience]):
                raise GrantError(f"link {i}: grant is not valid for audience {audience}")
            try:
                lim = g.limits
            except LimitError as e:
                raise GrantError(f"link {i}: {e}") from None

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
            if not verify(key, canonical_json(b), g.sig):
                raise GrantError(f"link {i}: bad signature")
            prev, prev_limits = g, lim
            link_limits.append(((g.iss, g.id), lim))

        if chain.leaf.sub != requester:
            raise GrantError("grant was issued to a different agent")

        allowed = self.root_policy(chain.root.iss, audience)
        if allowed is None:
            raise GrantError("root issuer is not a principal this service trusts")
        if not scopes_cover(allowed, chain.root.scopes):
            raise GrantError("root grant exceeds what its principal may authorize here")

        revoked = self.revoked([(g.iss, g.id) for g in chain.links])
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
        """
        if not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
            raise GrantError("amount must be a non-negative integer", 400)
        try:
            for _, lim in authz.link_limits:
                lim.check_call(resource=resource, amount=amount, unit=unit)
            stateful = [x for x in authz.link_limits if x[1].stateful]
            if stateful:
                charge = amount if any(l.total is not None for _, l in stateful) else 0
                self.ledger.consume(stateful, charge, now)
                authz.charged = charge
        except LimitError as e:
            raise GrantError(str(e), e.status) from None

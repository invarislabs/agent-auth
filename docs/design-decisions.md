# Design decisions

Short records of the choices that shaped AgentAuth: what was decided, why, and what it costs. Add a new entry when a decision changes. Don't rewrite old ones; mark them superseded instead.

---

### DD-1: Self-certifying DIDs instead of registry-assigned IDs

**Decision.** An agent's DID is the digest of its own signed inception event (`did:agent:<multihash>`).

**Why.** An identifier the registry hands out is only as trustworthy as the registry. A self-certifying one can't be minted, reassigned or forged by anyone who doesn't hold the inception key, and anyone can check it offline.

**Cost.** DIDs aren't human-readable. Human-friendly names live in `meta` and aren't authoritative.

---

### DD-2: A KERI-style key event log with mandatory pre-rotation

**Decision.** Each identity has an append-only, hash-chained log. Every establishment event commits to the hash of the *next* key, and a rotation must reveal that key and be signed by it.

**Why.** Agents run in exposed environments, so their current key is the likeliest thing to leak. Pre-rotation means leaking it isn't enough to take over the identity. We borrowed the idea from KERI but kept the event model much smaller (no witnesses yet, one key per event, no multisig thresholds) to keep the protocol easy to implement.

**Alternatives.**
- `did:key`: no rotation at all.
- `did:web`: trusts DNS and the web host.
- Full KERI: powerful, but a large specification for a v0.

**Cost.** Operators have to look after two keys per identity. Losing the recovery key means the identity can't be rotated again, only deactivated.

---

### DD-3: Sign every request instead of issuing bearer tokens

**Decision.** Agents authenticate each request with an Ed25519 signature over its method, audience, path, body, timestamp, nonce and grant header (`AgentSig`).

**Why.** Bearer tokens leak through agent context: logs, prompts and tool outputs. A signature is worthless outside the one request it was made for.

**Alternatives.**
- **RFC 9421 HTTP Message Signatures.** Close in spirit. We chose a fixed, minimal signing string to avoid negotiating covered components. A future version may align with 9421.
- **DPoP.** Proof-of-possession for OAuth tokens, but it assumes an OAuth deployment.

**Cost.** Every request costs one signature (microseconds) and one verification. Services need a nonce cache.

---

### DD-4: Our own grant format rather than JWT, Macaroons or Biscuit

**Decision.** Grants are canonical-JSON bodies with detached Ed25519 signatures. Chains are a comma-separated list of links, each signed by the previous link's subject.

**Why.**
- **JWT:** allows many algorithms (a long history of `alg` confusion bugs), has no native model for multi-hop delegation, and its claims don't map cleanly onto per-link attenuation.
- **Macaroons:** attenuate beautifully, but rely on a shared HMAC root key, so only the issuer can verify them. We need anyone to be able to verify, with each hop signed by a *different* party.
- **Biscuit:** the closest match (public-key, attenuable, offline-verifiable) and a strong candidate for the future. Its Datalog policy language is more than v0 needed.

**Cost.** A custom format has to be implemented in each language. The [protocol spec](protocol.md) exists to make that feasible.

---

### DD-5: Services decide whom to trust (the root policy)

**Decision.** A grant chain is only accepted if its root issuer is a principal the *service* trusts, and only for the scopes the service allows that principal.

**Why.** There's no global authority on who may do what at your API. The service owner already knows which people and orgs are its customers. AgentAuth makes the chain from that principal to the calling agent verifiable, and leaves the root decision where it belongs.

**Cost.** Each service configures trust. `trust_principals({...})` covers the simple case, and a callable handles dynamic ones.

---

### DD-6: Grants are only valid under the issuer's current key

**Decision.** Each link records the issuer's `kid`. Verification fails if the issuer has rotated since the grant was issued.

**Why.** If a key was rotated *because* it leaked, grants signed with it must stop working. Accepting historical keys would require knowing *when* each grant was signed, which a compromised key could lie about.

**Cost.** Rotating an issuer invalidates everything it issued. Grants are meant to be short-lived (15 minutes by default, 24 hours at most), so re-issuing them is cheap.

---

### DD-7: Limits apply to the whole grant and fail closed

**Decision.** A grant's limits (resources, spend, rate, uses) apply to *every* scope in it. A resource-limited grant is refused at endpoints that don't declare a resource. Unknown limit fields make a grant invalid.

**Why.** Per-scope limits would make both the format and the narrowing rules much more complex. Failing open (ignoring a resource limit when an endpoint doesn't declare a resource) would silently widen authority, which is the one thing a limit must never do.

**Cost.** To give an agent differently limited capabilities, issue several grants. Services have to declare resources and costs on their endpoints.

---

### DD-8: Stateful limits are charged against every link, all-or-nothing

**Decision.** Budget, rate and use counters are kept per grant. Each call is charged atomically against every link in its chain that has one.

**Why.** Without this, an agent with a 50 USD budget could delegate 50 USD to each of ten sub-agents. Charging every link turns a parent's limit into a hard ceiling on everything beneath it.

**Cost.** The ledger is shared state that services must keep, and it has to be distributed (Redis or a database) once a service runs more than one replica.

---

### DD-9: A single registry as witness, not authority (for now)

**Decision.** One registry stores and serves logs. Clients replay logs rather than trusting its answers.

**Why.** It gives the security properties that matter most (no forgery, no key substitution) with a simple deployment.

**Cost.** The registry can withhold events or show different clients different logs. Multiple witnesses and clients that remember logs they've seen are on the [roadmap](roadmap.md).

---

### DD-10: Canonical JSON without floats

**Decision.** Signed payloads are JSON with sorted keys, no whitespace and UTF-8, and floats are rejected. Amounts are integers in the smallest unit.

**Why.** Float serialization differs across languages and is the classic way a "canonical" JSON scheme breaks. Without floats, and with the ASCII keys and safe-range integers AgentAuth uses, this produces the same bytes as RFC 8785 (JCS).

**Cost.** Money and other quantities have to be expressed as integers, such as cents, and the unit has to be stated.

---

### DD-11: Python and FastAPI first

**Decision.** The reference implementation is a Python package with FastAPI integrations and an SQLite-backed registry.

**Why.** Much agent tooling is written in Python, and FastAPI's dependency injection maps directly onto "authenticate, authorize, enforce limits".

**Cost.** Node/TypeScript agent ecosystems need a port. That's on the [roadmap](roadmap.md), and the [protocol spec](protocol.md) is the contract a port has to follow.

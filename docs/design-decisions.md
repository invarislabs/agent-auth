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

**Cost.** The registry can withhold events or show different clients different logs. Partly addressed in v0.4 by DD-15.

---

### DD-10: Canonical JSON without floats

**Decision.** Signed payloads are JSON with sorted keys, no whitespace and UTF-8, and floats are rejected. Amounts are integers in the smallest unit.

**Why.** Float serialization differs across languages and is the classic way a "canonical" JSON scheme breaks. Without floats, and with the ASCII keys and safe-range integers AgentAuth uses, this produces the same bytes as RFC 8785 (JCS).

**Cost.** Money and other quantities have to be expressed as integers, such as cents, and the unit has to be stated.

---

### DD-11: Python and FastAPI first

**Decision.** The reference implementation is a Python package with FastAPI integrations and an SQLite-backed registry.

**Why.** Much agent tooling is written in Python, and FastAPI's dependency injection maps directly onto "authenticate, authorize, enforce limits".

**Cost.** Other ecosystems need a port. A TypeScript verifier now exists (`ts/`, see DD-19); signing and issuing from TypeScript are on the [roadmap](roadmap.md). The [protocol spec](protocol.md) and the shared test vectors are the contract a port has to follow.

---

### DD-12: Fail closed on infrastructure errors, with a distinct status

**Decision.** When verification can't be completed because something it depends on failed (key resolution, replay cache, usage ledger, revocation check, root policy), the request is refused with **503**, never allowed. The one exception is the registry's own request rate limiter, which lets traffic through when Redis is down.

**Why.** Each of those checks exists to stop something; skipping it when its backend is down would turn an outage into a bypass. 503 rather than 401/403 lets clients and operators tell "you're not allowed" from "we couldn't check". The rate limiter is the exception because it protects availability: refusing everything while Redis is down would cause the outage it exists to prevent.

**Cost.** Availability of a relying service now depends on the registry and Redis. Caches (`ttl`) soften the registry dependency.

---

### DD-13: Strict parsing everywhere, without changing formats

**Decision.** v0.4 keeps every wire format and version string, but rejects anything that isn't exactly what the reference implementation produces: duplicate header parameters, unknown fields, non-canonical base64url, out-of-range integers, malformed DIDs.

**Why.** Lenient parsing is how two implementations come to disagree about what a signed object means. Every leniency removed was one an attacker could have used (smuggling a second `did=`, re-encoding a signature) or one that turned bad input into a 500. Because valid v0.3 output is unaffected, no version bump was needed.

**Cost.** A third-party client that produced sloppy but previously accepted output (e.g. a 12-character nonce) must be fixed.

---

### DD-14: Redis for shared verifier state, behind small interfaces

**Decision.** Replay protection and usage limits are interfaces (`check_and_store`; `consume`/`refund`/`usage`) with in-memory defaults and Redis implementations. The Redis ledger does check-and-charge for all links in one Lua script.

**Why.** These are the two pieces of state that must be shared exactly (an atomic test-and-set, an atomic multi-key check-and-increment) for the security properties to hold across replicas. Redis does both in one round-trip with well-understood semantics; a SQL implementation is possible behind the same interface.

**Cost.** One more dependency for multi-replica services. Redis Cluster isn't supported (a chain's counters must be updated together).

---

### DD-15: Detect equivocation on the client, with pins and pools

**Decision.** Instead of trusting a registry's view, relying services remember the newest verified log per DID (pins) and can read from several independent registries (`RegistryPool`), requiring every log to be a prefix of the longest.

**Why.** Events are self-certifying, so a longer valid log is always more current and a fork always means a compromised key or a lying registry. Both checks need no new wire format and no coordination between registries.

**Cost.** Doesn't catch a split view shown to a client that has never seen the other branch and talks to one registry. That needs gossip or a transparency log (roadmap).

---

### DD-16: Revocation answers carry their own proof; unproven claims are denied by default

**Decision.** The registry returns the issuer-signed revocation with every "revoked" answer, and services verify it against the issuer's key history. A claim without a valid proof is still treated as revoked by default (`on_unproven="deny"`), and logged.

**Why.** The proof stops a registry from silently revoking grants nobody revoked, which is a denial-of-service lever. Denying unproven claims by default keeps v0.3 registries (which send no proofs) working and keeps the failure mode on the safe side; operators who worry more about that DoS can switch to `ignore`.

**Cost.** One issuer-log fetch per revoked grant the first time it's seen (revoked results are cached forever).

---

### DD-17: Crash-safe rotation with a pending key file

**Decision.** Before a rotation is submitted, the key it commits to next is written to `<name>.pending.json`. The rotation is resumed from that file if the process dies.

**Why.** In v0.3, a crash between the registry accepting a rotation and the SDK saving the new keys lost the new recovery key, leaving an identity that could never rotate or self-deactivate again.

**Cost.** One more file to protect (it's a recovery key) during the rotation window.

**Revised after the October 2026 review.** A pending key the registry hasn't committed to is reused only if its file is authenticated: encrypted with the identity's passphrase in the v2 format, which binds it to this DID and role. Otherwise the file is moved aside and a fresh key is used. Without this, anyone able to write to the recovery directory could plant a pending file and choose the identity's next key.

---

### DD-18: One encoding per grant (canonical payloads, ASCII audiences and scopes)

**Decision.** A grant's payload must be exactly `canonical_json(body)`, byte for byte. `aud` and `scope` must already be sorted and de-duplicated, with `aud` lower-cased, and both are printable ASCII. Stateful limits can't be combined with audience `"*"`.

**Why.** The October 2026 review found that the same signed token could be read differently by different JSON parsers: a duplicate `sub` key (Python keeps the last one), `1.0` versus `1`, or Unicode case folding of audiences, which differs between languages. With a second implementation (TypeScript), any such ambiguity becomes a way to make two verifiers disagree. Allowing exactly one encoding removes the whole class. Stateful limits on `"*"` would be enforced once per service, since every service keeps its own ledger, so they multiply instead of limiting.

**Cost.** Grants with non-ASCII audiences or scopes, or with budgets on `"*"`, must be re-issued. Grants from the reference SDK were already canonical.

---

### DD-19: A second implementation held to shared test vectors

**Decision.** The TypeScript verifier is a check-for-check port of the Python verifier. Both run the same deterministic test vectors (`test-vectors/`), which are generated from the Python code; CI fails if they're stale. Where the protocol depends on string semantics, TypeScript reproduces Python's (`str.isspace()`, code-point ordering).

**Why.** A protocol is only as precise as its least careful implementation. Generating the vectors from the reference, and checking that the generator's expectations hold before writing them, keeps the spec, the reference and the port from drifting apart. Porting itself surfaced three differences (number parsing, whitespace, sort order) that are now pinned down by vectors.

**Cost.** Changing a verification rule means regenerating the vectors and updating both implementations in the same change.

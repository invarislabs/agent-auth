# Glossary

**Agent.** An autonomous piece of software that acts, such as calling APIs, spending money or delegating work. In AgentAuth, anything with a `did:agent:` identity. Humans and orgs use the same kind of identity when they act as principals.

**AgentGrant.** The HTTP header that carries a grant chain, root first. See the [protocol](protocol.md#4-capability-grants-agentgrant).

**AgentSig.** The `Authorization` scheme for signed requests. See the [protocol](protocol.md#3-request-authentication-agentsig).

**Attenuation.** Narrowing authority when delegating. A child grant may only have a subset of its parent's scopes, audiences, validity window, depth and limits.

**Audience (`aud`).** The `host[:port]` a request or grant is meant for. Services reject anything addressed to another audience.

**Chain.** An ordered list of grants from a principal down to the agent making the request. Each link is issued by the previous link's subject.

**Controller.** An identity (usually a human or org) named in an agent's inception event. It countersigns the agent's creation, can list the agents it controls, and can deactivate them.

**Current key.** The key an identity signs with right now. It's identified by its `kid`.

**Deactivation.** A permanent end to an identity. It's signed with the recovery key or by the controller. Afterwards the DID has no key, and every chain through it fails.

**Delegation depth (`depth`).** How many more times a grant's subject may re-delegate. `0` means it can't delegate at all.

**DID (Decentralized Identifier).** A W3C-standard identifier. AgentAuth's method is `did:agent:`, and the identifier is derived from the identity's inception event.

**DID document.** The public description of a DID's current keys, served by the registry in W3C DID resolution format.

**Grant.** A signed capability: *issuer lets subject do these scopes at these audiences until this time, with these limits.*

**Inception.** The first event in an identity's log. It sets the first key, commits to the next one, and names the controller.

**Issuer (`iss`).** The identity that signed a grant.

**Key event log (KEL).** An identity's append-only, hash-chained list of signed events: inception, rotations and at most one deactivation. Replaying it gives the current key.

**Key ID (`kid`).** `did#key-N`, where N is the sequence number of the event that established the key.

**Limits.** Optional restrictions on a grant: `resources`, `spend` (`per_call`, `total`), `rate` and `uses`. See the [protocol](protocol.md#5-limits).

**Multikey.** A self-describing public key encoding (`z6Mk…` for Ed25519), shared with `did:key`.

**Nonce.** A random, single-use value in each signed request. It stops replays.

**Pre-rotation.** Committing to the hash of the next key in advance, so a rotation must be signed by a key that has never been used or exposed.

**Principal.** The root of a grant chain: the human or org whose authority an agent is exercising. A service decides which principals it trusts.

**Recovery key.** The pre-committed next key. It's needed to rotate or self-deactivate, and should be stored away from the agent.

**Registry.** The service that stores key event logs and revocations. It's a witness, not an authority: it validates events but can't forge them.

**Relying service (relying party).** Any API that verifies agent requests and grants.

**Revocation.** An issuer-signed statement that one of its grants is withdrawn. It also invalidates every delegation beneath that grant.

**Root policy.** A service's rule for which principals may authorize which scopes there.

**Rotation.** Replacing an identity's current key with its pre-committed next key, and committing to a new next key.

**Scope.** A dotted action name (`files.read`), optionally ending in a wildcard (`files.*`), or `*` for everything.

**Subject (`sub`).** The identity a grant is issued to.

**Usage ledger.** The service-side record of spend, call rate and use counts for each grant.

**Witness.** A party that records and vouches for events without being able to create them. The registry is currently the only witness.

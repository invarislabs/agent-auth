# Threat model

This document covers what AgentAuth protects, whom it protects against, and where the gaps are as of v0.3. Report security issues privately to the maintainers, not in public issues.

## Assets

| Asset | Why it matters |
|---|---|
| Agent private keys (current and recovery) | Whoever holds them *is* the agent |
| Principal (human/org) keys | They are the root of every grant chain |
| Grants | They describe what an agent may do, and on whose behalf |
| Key event logs | They decide which key is current for each DID |
| Revocation records | Revoked authority must stay dead |
| Usage ledger | It enforces budgets, rate limits and use counts |

## Trust assumptions

- **Ed25519 and SHA-256 are secure**, and keys are generated with a good randomness source (the `cryptography` library, backed by the OS).
- **Relying services are honest about themselves.** They configure their own audiences and root policy correctly, and declare resources and costs truthfully.
- **Clocks are roughly synchronized**, within 60–120 seconds.
- **The registry is available**, and honest about *what it has*, but it isn't trusted to forge anything. (Replaying logs protects against forgery. It doesn't protect against the registry withholding events or showing different clients different logs; see below.)

## Adversaries and mitigations

### Network attacker (sees, replays or modifies traffic)

| Attack | Mitigation |
|---|---|
| Replay a captured request against the same service | Single-use nonce per DID within the replay window, plus a ±120 s timestamp window |
| Replay it against a different service | The signature covers the audience (`host[:port]`), and each service only accepts its own |
| Replay it against a different endpoint, or with a changed body | The signature covers method, path, query and a digest of the body |
| Swap or strip the `AgentGrant` header | The signature covers a digest of the grant header |
| Steal credentials in transit | There are none to steal. Requests carry signatures, never secrets. (Use TLS anyway: request bodies may be sensitive.) |

### A stolen grant

A grant names its subject. Using it requires signing the request with the **subject's** key, so a stolen grant by itself is useless.

### Theft of an agent's current key

**Impact:** the attacker can act as the agent until the key is rotated or the agent is deactivated.

- **Can't take over the identity.** Rotation requires the pre-committed recovery key.
- **Recovery:** the owner rotates (with the recovery key) or deactivates (with the recovery key or the controller's key). Services pick up the change within their cache TTL. A rotation is picked up immediately if the legitimate agent then presents the newer `kid`.
- **Damage is capped** by whatever limits its grants carry: scopes, audiences, TTL, resources, budget, rate and uses.

### Theft of both current and recovery keys

**Impact:** full control of the identity, including rotating it to keys only the attacker knows.

- **Mitigation today:** keep the recovery key off the agent's host (separate machine, vault, KMS or HSM). If the agent has a controller, the controller can still deactivate it.
- **Gap:** without a controller, there's no recovery. Consider making controllers mandatory for high-value agents.

### A malicious or compromised agent in a delegation chain

| Attack | Mitigation |
|---|---|
| Delegate wider scopes, audiences, lifetime or depth than it holds | Checked at issue time by the SDK, and again independently by every verifier |
| Drop or loosen a parent's limits | Every link's limits are enforced, and narrowing is checked on every link |
| Split a budget among many sub-agents to multiply it | Counters are charged against **every** link in the chain, so a parent's budget, rate and uses are shared by everything beneath it |
| Keep acting after its authority is withdrawn | Revoking any upstream grant, or deactivating any upstream identity, invalidates the chain |
| Revoke grants it didn't issue | Revocations are keyed by *(issuer, grant id)* and signed by the issuer |

### A principal a service doesn't trust

Grants rooted in anyone other than the principals in the service's root policy are rejected. A trusted principal can't grant more than the policy allows it at that service.

### Resource-name tricks

A requested resource containing a `.` or `..` path segment, a `*`, or control characters is rejected before matching, so `/reports/../hr/salaries.csv` can't slip past a `/reports/*` limit. Services should still canonicalize resource names consistently. See the [integration guide](integration-guide.md#3-resource-and-spend-limits).

### A malicious registry

| Attack | Mitigation |
|---|---|
| Invent an identity, or reassign a DID to other keys | DIDs are self-certifying. Services replay the full log (`RegistryKeyResolver(verify_logs=True)`, the default). |
| Forge a rotation or deactivation | Every event must be signed, chained, and satisfy pre-rotation |
| Squat on a controller relationship | The controller must countersign the inception with its current key |
| Forge a revocation | Revocations must be signed by the grant's issuer. Services currently trust the registry's answer to a revocation check. See the gaps below. |

## Known gaps (v0.3)

### Registry equivocation

A malicious registry could **withhold** events (for example, hide a deactivation so a compromised agent keeps working) or show **different logs to different clients**. It could also falsely claim a grant is revoked (denial of service), or falsely claim it isn't.

*Planned:* multiple independent witnesses that countersign events, clients that remember the logs they've seen so they can spot conflicting versions, and signed revocation proofs that services verify themselves.

### Revocation and deactivation aren't instant

Services cache for performance. By default a deactivation takes effect within 30 s, and a grant revocation within 5–10 s. Set the TTLs to 0 for sensitive endpoints.

### State is in memory and per process

The **nonce cache** and **usage ledger** live in memory, which has two consequences:

- **Across replicas:** a request could be replayed against another replica within the timestamp window, and budgets, rates and uses are counted per replica, so N replicas allow up to N× the limit.
- **On restart:** counters reset.

*Mitigation:* back both with Redis or your database before running more than one replica. See [operations](operations.md#scaling).

### Services must declare costs honestly

Spend limits only bind endpoints that report an `amount`. A service that forgets to (or lies) isn't limited. This is inherent: AgentAuth can't observe what a call really costs.

### Grants are tied to the issuer's current key

After an issuer rotates, its outstanding grants stop verifying and have to be re-issued. This is safe, since a compromised old key can't keep issuing valid grants, but it's operationally noisy for long-lived grants. Keep grants short.

### No registration rate limiting

Anyone can register identities. A registry exposed to the internet should sit behind rate limiting or authentication.

### Timing and side channels

Signature checks use the `cryptography` library. Other comparisons (nonces, kids, digests) aren't constant-time. None of them are secret values, but this hasn't been reviewed.

### Not independently audited

The design and code haven't had an external security review. Don't rely on AgentAuth to protect high-value assets until they have.

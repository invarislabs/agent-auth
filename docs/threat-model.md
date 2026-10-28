# Threat model

This document covers what AgentAuth protects, whom it protects against, and where the gaps are as of v0.4. Report security issues privately (see [SECURITY.md](../SECURITY.md)), not in public issues.

> **Status.** v0.4 is a hardened implementation with adversarial, concurrency and end-to-end tests. It has **not** had an independent security audit. "Mitigated" below means "designed and tested against", not "verified by a third party".

## Assets

| Asset | Why it matters |
|---|---|
| Agent private keys (current and recovery) | Whoever holds them *is* the agent |
| Principal (human/org) keys | They are the root of every grant chain |
| Grants | They describe what an agent may do, and on whose behalf |
| Key event logs | They decide which key is current for each DID |
| Revocation records | Revoked authority must stay dead |
| Usage ledger | It enforces budgets, rate limits and use counts |
| Replay cache | It makes each signed request single-use |
| Audit log | It answers "who authorized this?" after the fact |

## Trust assumptions

- **Ed25519 and SHA-256 are secure**, and keys are generated with a good randomness source (the `cryptography` library, backed by the OS).
- **Relying services are honest about themselves.** They configure their own audiences and root policy correctly, and declare resources and costs truthfully.
- **Clocks are roughly synchronized**, within 60–120 seconds.
- **Shared state is shared.** Every process that verifies requests for an audience uses the same replay cache and usage ledger (Redis), and that store is not reachable by attackers.
- **At least one registry is honest about what it has** — or, with a single registry, it doesn't equivocate to clients that have never seen the other branch (see below). Registries are never trusted to *forge* anything.

## Adversaries and mitigations

### Network attacker (sees, replays or modifies traffic)

| Attack | Mitigation |
|---|---|
| Replay a captured request against the same service | Single-use nonce per DID within the replay window, plus a ±120 s timestamp window. With several replicas, the nonce store is shared through Redis (`RedisNonceCache`, one atomic `SET NX`); `agentauth serve --workers N` refuses to start without it. |
| Replay it against a different service | The signature covers the audience (`host[:port]`), and each service only accepts its own |
| Replay it against a different endpoint, or with a changed body | The signature covers method, raw path and query, and a digest of the body |
| Swap or strip the `AgentGrant` header | The signature covers a digest of the grant header |
| Smuggle a second `did=` (or any parameter) into the header | Duplicate parameters invalidate the header |
| Send a request signed for audience A to host B of the same app (to use a grant only valid at A) | Opt-in `RequestVerifier(bind_host=True)` requires the signed audience to equal `Host`. Needed only when one app serves several audiences and routes by host. |
| Configure a replay cache that forgets nonces before their timestamps expire | `RequestVerifier` refuses a cache whose TTL is shorter than the replay window |
| Re-encode a signature or grant (padding, stray characters) | Only canonical base64url is accepted |
| Steal credentials in transit | There are none to steal. Requests carry signatures, never secrets. (Use TLS anyway: request bodies and grants may be sensitive.) |

### A stolen grant

A grant names its subject. Using it requires signing the request with the **subject's** key, so a stolen grant by itself is useless.

### Theft of an agent's current key

**Impact:** the attacker can act as the agent until the key is rotated or the agent is deactivated.

- **Can't take over the identity.** Rotation requires the pre-committed recovery key.
- **Recovery:** the owner rotates (with the recovery key) or deactivates (with the recovery key or the controller's key). Services pick up the change within their cache TTL. A rotation is picked up immediately if the legitimate agent then presents the newer `kid`.
- **Damage is capped** by whatever limits its grants carry: scopes, audiences, TTL, resources, budget, rate and uses.

### Theft of both current and recovery keys

**Impact:** full control of the identity, including rotating it to keys only the attacker knows.

- **Mitigation:** keep the recovery key off the agent's host. The SDK accepts any `Signer` (an object with `public_multikey` and `sign()`), so the recovery key can live in an HSM, a KMS or a signing service; the default key files can be encrypted (scrypt N=2¹⁷ + AES-256-GCM) and stored in a separate directory. If the agent has a controller, the controller can still deactivate it.
- **Gap:** without a controller, there's no recovery. Consider making controllers mandatory for high-value agents.

### Losing key material by accident

| Failure | Mitigation |
|---|---|
| Crash in the middle of a rotation, losing the new recovery key | `rotate_and_save` (and `agentauth rotate`) writes the new next key to `<name>.pending.json` *before* submitting, and resumes on the next run |
| A registry that drops a submitted event, so the SDK swaps to keys nobody else knows | `commit()` only applies an event the registry's replayed log actually contains |
| Torn or partially written key files | Writes go to a uniquely named temp file (`O_EXCL`, `O_NOFOLLOW`, mode 0600), are fsynced, renamed, and the directory is fsynced |
| A pre-planted symlink at the temp path redirecting the secret (affected v0.3) | Temp names are random and never follow symlinks |
| Group/world-readable key files | Loading warns |
| A tampered key file with huge scrypt parameters (memory/CPU exhaustion) | Parameters are bounded |

### A malicious or compromised agent in a delegation chain

| Attack | Mitigation |
|---|---|
| Delegate wider scopes, audiences, lifetime or depth than it holds | Checked at issue time by the SDK, and again independently by every verifier |
| Drop or loosen a parent's limits | Every link's limits are enforced, and narrowing is checked on every link |
| Add a constraint field verifiers don't know, hoping they ignore it | Unknown grant fields invalidate the grant |
| Split a budget among many sub-agents to multiply it | Counters are charged against **every** link in the chain, so a parent's budget, rate and uses are shared by everything beneath it |
| Issue a grant to itself, or repeat a link | `iss == sub` and duplicate links are rejected |
| Keep acting after its authority is withdrawn | Revoking any upstream grant, or deactivating any upstream identity, invalidates the chain |
| Revoke grants it didn't issue | Revocations are keyed by *(issuer, grant id)* and signed by the issuer |

### A buggy or hostile service endpoint

| Problem | Mitigation |
|---|---|
| Refunding more than was charged, minting budget | `refund()` is capped at what the request was charged |
| Concurrent requests racing past a budget | Check-and-charge is atomic (a lock in-process, one Lua script in Redis) and tested under thread and multi-process load |
| Ledger store down | The request is refused (503); limits never fail open |
| Audit log can't be written | An allowed call is refunded and refused (503): no charged-but-unaudited actions |

### A principal a service doesn't trust

Grants rooted in anyone other than the principals in the service's root policy are rejected. A trusted principal can't grant more than the policy allows it at that service.

### Resource-name tricks

A requested resource containing a `.` or `..` path segment, a `*`, or control characters is rejected before matching, so `/reports/../hr/salaries.csv` can't slip past a `/reports/*` limit. Services should still canonicalize resource names consistently (for example, decide whether `%2F` means `/`). See the [integration guide](integration-guide.md#3-resource-and-spend-limits).

### A malicious registry

| Attack | Mitigation |
|---|---|
| Invent an identity, or reassign a DID to other keys | DIDs are self-certifying. Services replay the full log (`RegistryKeyResolver(verify_logs=True)`, the default). |
| Forge a rotation or deactivation | Every event must be signed, chained, and satisfy pre-rotation |
| Squat on a controller relationship | The controller must countersign the inception with its current key. The registry re-checks that key under the controller's write lock, in the same transaction as the insert, so a rotation can't race it. |
| Append a "controller deactivation" signed by a key the controller never held | Clients bind controller signatures to the controller's own verified log (`bound_controller_check`, used by `RegistryClient.verified_state`, `RegistryKeyResolver` and `RegistryPool`; the TypeScript `RegistryClient` does the same). A signature-only check would accept it. |
| One pool member serves an invalid but longer log, to win the longest-log merge | `RegistryPool` verifies each member's log before merging and ignores invalid ones |
| Roll a log back (e.g. hide a deactivation) after a service has seen the newer version | The resolver pins the newest `(seq, digest)` it verified per DID (in memory, or persistently with `SQLitePins`). A shorter or different log raises `EquivocationError` and requests fail with 503. |
| Withhold an event the service has never seen | With `RegistryPool`, events are written to several registries and reads take the longest consistent log, so *every* registry must withhold it. Every registry's revocation proof is checked, so one registry can't mask another's. |
| Serve two different histories (fork) | Detected when one client sees both: across registries in a pool, or over time through pins |
| Claim a grant is revoked when it isn't (denial of service) | The registry returns the issuer-signed revocation as a proof; `RegistryRevocationChecker` verifies it against the issuer's key history. Unproven claims are denied by default (fail closed) and counted; `on_unproven="ignore"` honours only proven ones. |
| Hide a revocation | Not detectable with one registry. With a pool, hiding requires all of them. |
| Forge a revocation | Revocations must be signed by the grant's issuer |

### Registry abuse (denial of service)

| Attack | Mitigation |
|---|---|
| Large or slow request bodies | Bodies over the limit (16 KiB default) are refused before being read (413); a body that takes longer than 10 s to arrive is refused (408) |
| Unbounded metric labels (arbitrary HTTP methods) | Methods outside the standard set are counted as `OTHER` |
| Spoofed or junk `X-Forwarded-For` | Only trusted hops are read, all header lines are joined, and a value that isn't an IP address falls back to the socket peer. IPv6 clients are counted per /64. |
| A slow or hung Redis stalling every request | The rate limiter runs off the event loop with a 250 ms budget, and fails open |
| Database lock or pool exhaustion | Answered with 503 and `Retry-After`, not 500 |
| Unbounded key event logs | At most 10,000 events per identity |
| Flooding registration or reads | Per-address rate limits (shared through Redis when configured); optional registration token |
| Making relying services hammer the registry by presenting fake newer `kid`s | Forced refreshes are limited to one per DID per second |
| Crafted JSON (deep nesting, NaN, duplicate keys, wrong types) causing 500s | Strict parsing and type checks; fuzz-tested to never return 5xx |

## Known gaps (v0.4)

### Split views against a single client

A registry can show a client that has never seen the other branch a consistent but different history (for example, a fork created with a stolen recovery key), and can hide events from a client that only ever talks to it. Pins and pools narrow this a lot but don't close it. Closing it needs gossip between clients or a public transparency log with signed tree heads; that's on the [roadmap](roadmap.md).

### "Not revoked" can't be proven

Revocation proofs show that something *was* revoked. Nothing proves the negative, so a lone dishonest registry can still hide a revocation (use a pool).

### Revocation and deactivation aren't instant

Services cache for performance. By default a deactivation takes effect within 30 s, and a grant revocation within 5–10 s. Set the TTLs to 0 for sensitive endpoints.

### Shared state has to be configured

The defaults (`NonceCache`, `UsageLedger`) are in-memory and per process, which is only correct for exactly one process. Running more than one worker or replica without Redis allows a replay once per process and N× every limit. `agentauth serve` refuses `--workers > 1` without Redis, but a service you build yourself (or a registry started directly with `uvicorn --workers`) can't be checked for you. Redis itself must be persistent (AOF) if budgets must survive a Redis restart.

### Services must declare costs honestly

Spend limits only bind endpoints that report an `amount`. A service that forgets to (or lies) isn't limited. This is inherent: AgentAuth can't observe what a call really costs.

### Grants are tied to the issuer's current key

After an issuer rotates, its outstanding grants stop verifying and have to be re-issued. This is safe, since a compromised old key can't keep issuing valid grants, but it's operationally noisy for long-lived grants. Keep grants short.

### Audit logs are tamper-evident, not tamper-proof

Hash-chaining and signing detect edits, but truncating the newest entries is only detectable against a head digest exported elsewhere. Export `AuditLog.head()` to a separate system.

### Multi-audience budgets are per service

A grant listing several audiences with a budget, rate or use limit is enforced by each service's own ledger. Two services that don't share a ledger each allow the full limit. For that reason a stateful limit can't be combined with the audience `"*"` (any service at all); with explicit audiences, either point the services at one shared `RedisUsageLedger` or issue one grant per service.

### Key directory write access

Key files are protected against being read (mode 0600, optional encryption) and against being swapped between identities or roles (the encryption binds DID, role and public key). Someone who can *write* to the key directory can still delete files, or plant a plaintext key file when no passphrase is configured. The SDK never adopts a planted pending-rotation key the registry hasn't committed to, and refuses plaintext files when a passphrase is set, but keep key directories writable only by the agent's user.

### WebSocket and streaming responses

`AgentAuthMiddleware` authorizes a WebSocket at the handshake and an SSE stream when it opens. A grant that expires or is revoked during a long-lived connection doesn't end it. Bound connection lifetimes in the application if that matters.

### Same key under two DIDs

The request signature doesn't cover the `did` parameter. If one key is the current key of two DIDs (only possible if its holder registered both), a request signed for one could be replayed as the other within the window. Don't reuse keys across identities; the SDK never does.

### Rate limiting fails open

If Redis is down, the registry's rate limiter lets requests through (and logs an error), on purpose: refusing every request would be the outage the limiter exists to prevent. Replay protection and usage limits fail closed.

### Timing and side channels

Signature checks use the `cryptography` library. Other comparisons (nonces, kids, digests) aren't constant-time; none of them are secret. The registration token is compared in constant time.

### Not independently audited

The design and code have had an internal review ([October 2026](security-audit-2026-10.md)), but no independent, external security audit. An internal review by the people who wrote the code isn't a substitute. Don't rely on AgentAuth to protect high-value assets until an external audit has happened; [audit-brief.md](audit-brief.md) is the starting point for one.

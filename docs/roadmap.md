# Roadmap

What's shipped, and what's next.

## Shipped

### v0.1: Identity
- Self-certifying `did:agent:` identifiers
- Key event log with mandatory pre-rotation
- Controller countersignature and kill switch
- Signed requests (`AgentSig`) with audience, body, timestamp and nonce binding
- Encrypted keys, with current and recovery keys stored separately
- Registry service, SDK and CLI

### v0.2: Delegated authority
- Scoped, short-lived capability grants
- Delegation chains that can only narrow (scopes, audiences, lifetime, depth)
- Root policy: each service decides which principals it trusts
- Revocation, and cascading deactivation

### v0.3: Limits
- Resource patterns, per-call and total spend, rate limits and use counts
- Limits enforced on every link, with shared counters so sub-agents can't multiply a budget
- Refunds, fail-closed resource checks, path-traversal protection

### v0.4: Production hardening (released 2026-10-28)

Install with `pip install invaris-agentauth`, or run the registry image `ghcr.io/invarislabs/agent-auth:0.4.0`. See the [changelog](../CHANGELOG.md) for everything in the release.

- **Shared state:** Redis-backed replay cache and atomic (Lua) usage ledger; ledger counters pruned/expired with their grants
- **Registry storage:** PostgreSQL support, versioned schema with migrations (`agentauth db migrate/status/verify`), integrity verification, SQLite durability and thread-safety fixes
- **Registry service:** env configuration validated at startup, body-size limits, per-address rate limits, optional registration token, `/readyz`, Prometheus `/metrics`, JSON logs with request ids, pagination
- **Dishonest-registry defences:** log pinning (rollback/fork detection), `RegistryPool` cross-checking several registries, signed revocation proofs verified by services
- **Key custody:** crash-safe rotation, hardened key files (O_EXCL/fsync, recorded KDF parameters, scrypt N=2¹⁷), `Signer` interface for HSM/KMS-held keys
- **Audit log:** hash-chained, optionally signed log of authorization decisions
- **Integrations:** framework-agnostic ASGI middleware; MCP servers (per-tool scopes), tested with the official MCP SDK
- **Stricter verification** everywhere, with every dependency failure failing closed (503)
- **Deployment:** Dockerfile (hash-locked dependencies, non-root), docker compose stack (PostgreSQL, Redis, migration job)
- **CI:** Python 3.10–3.14 with Redis and PostgreSQL services, minimum-dependency and httpx-only jobs, ruff, mypy, pip-audit, bandit, CodeQL, package and image builds
- **Releases:** published on PyPI as `invaris-agentauth` (import name and CLI stay `agentauth`) through trusted publishing, and the registry image on `ghcr.io/invarislabs/agent-auth`, both built by a release workflow
- **Internal security review** of the protocol core, the registry and the SDK, with every finding fixed and covered by a regression test ([security-audit-2026-10.md](security-audit-2026-10.md)). This was not an independent audit.
- **TypeScript verifier** (`ts/`) for Node, Deno, Bun, browsers and edge runtimes, with no runtime dependencies. It verifies key event logs, signed requests, grant chains and revocation proofs, and its registry client binds controller keys and pins logs.
- **Shared test vectors** (`test-vectors/`) that both implementations must pass, checked in CI

### Tooling
- Compatibility with both `httpx` and `httpx2` clients

## Next

### 1. Closing the remaining registry gaps
- Gossip of verified log heads between relying services, or a transparency log with signed tree heads, so split views are detectable even for a client that only talks to one registry
- Registry-signed receipts for accepted events

### 2. Stronger key custody
- Ready-made `Signer` adapters for cloud KMS and PKCS#11 (the interface exists; no adapters ship yet)
- Optional multi-key thresholds (e.g. 2-of-3 recovery keys). This needs a new event format.

### 3. Ecosystem
- **TypeScript issuing and signing.** The verifier has shipped; signing requests and issuing grants from Node is next, followed by publishing to npm.
- **Adapters** for popular agent frameworks
- **Helm chart / Kubernetes manifests** for the registry
- A **standalone written spec**, and possible alignment with RFC 9421 HTTP Message Signatures

### 4. Operations
- A shared (Redis/SQL) implementation of the log-pin store, so detection is shared across replicas
- An exporter for audit-log heads

### 5. Independent security review
An external audit of the protocol and both implementations before 1.0. The internal review (October 2026) is done. [audit-brief.md](audit-brief.md) describes the scope, the threat model and where to start.

## Open questions

- **Biscuit.** Should grants move to Biscuit tokens for a richer policy language, or stay minimal?
- **Per-scope limits.** Should one grant be able to carry different limits for different scopes, or should "one grant per differently-limited capability" remain the rule?
- **Mandatory controllers.** Should every agent be required to have a controller, so there's always a way to shut it down?

Ideas and feedback are welcome as GitHub issues.

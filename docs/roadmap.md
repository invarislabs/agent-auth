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

### Tooling
- Compatibility with both `httpx` and `httpx2` clients
- GitHub Actions CI on Python 3.10–3.13, plus a job with plain `httpx` only

## Next

### 1. Audit log
A tamper-evident, hash-chained log of authorized actions. Each entry records the full principal → agent chain, the scope, the resource and the amount, so "who authorized this?" can be answered after the fact.

### 2. Production hardening
- Redis-backed nonce cache and usage ledger (multi-replica safe)
- Postgres storage for the registry
- Rate limiting and optional authentication for registration
- Pruning of ledger counters for expired grants
- Structured logging and metrics

### 3. Protection against a dishonest registry
- Multiple independent witnesses countersigning events
- Clients that remember logs they've seen and detect conflicting versions
- Signed revocation proofs that services verify themselves, instead of trusting a registry answer

### 4. Stronger key custody
- Recovery keys held in a KMS or HSM (cloud KMS, PKCS#11)
- Optional multi-key thresholds (e.g. 2-of-3 recovery keys)

### 5. Ecosystem
- **TypeScript verifier and client.** Much agent tooling runs on Node.
- **MCP integration.** Let MCP servers authenticate calling agents and require grants per tool.
- **Adapters** for popular agent frameworks
- **Docker image and Helm chart** for the registry
- A **standalone written spec**, and possible alignment with RFC 9421 HTTP Message Signatures

### 6. Independent security review
An external audit of the protocol and implementation before 1.0.

## Open questions

- **Biscuit.** Should grants move to Biscuit tokens for a richer policy language, or stay minimal?
- **Per-scope limits.** Should one grant be able to carry different limits for different scopes, or should "one grant per differently-limited capability" remain the rule?
- **Mandatory controllers.** Should every agent be required to have a controller, so there's always a way to shut it down?

Ideas and feedback are welcome as GitHub issues.

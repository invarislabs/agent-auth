# External security audit brief

This brief is for an independent security firm or researcher auditing AgentAuth.
It covers what the system protects, what is in scope, where the risk concentrates, and
what has already been checked internally, so the audit's time goes where it adds
the most.

## The system in one paragraph

AgentAuth gives AI agents verifiable identities and delegated, limited authority.

- **Identity.** An agent is a self-certifying `did:agent:` identifier backed by a hash-chained key event log with mandatory pre-rotation.
- **Requests.** It authenticates each HTTP request with an Ed25519 signature (`AgentSig`) bound to the audience, method, target, body, time, nonce and presented grants.
- **Authority.** It proves authority with a chain of signed capability grants (`AgentGrant`). Each link can only narrow scopes, audiences, lifetime and limits (resources, spend, rate, uses).
- **The registry.** It stores logs and revocations but is not trusted: clients replay logs, pin what they've seen, and can cross-check several registries.

Full details: [protocol](protocol.md), [architecture](architecture.md),
[threat model](threat-model.md) and [design decisions](design-decisions.md).

## Assets and attacker goals

| Asset | Attacker goal |
|-------|---------------|
| An agent's authority (grants) | Act with more scope, audience, lifetime or budget than granted. Use another agent's grant. |
| An agent's identity | Sign as an agent without its current key. Take over recovery (the next key). |
| Control relationships | Deactivate or register under a controller without its key. |
| Revocation status | Keep a revoked grant working. Make a valid grant look revoked. |
| Usage limits | Spend beyond a budget, or exceed rate or use limits, for example across replicas or delegation branches. |
| Registry availability | Take the registry or relying services down cheaply. |
| Audit trail | Make decisions go unrecorded, or rewrite history undetectably. |

## Scope

| Area | Paths | Priority |
|------|-------|----------|
| Protocol specification | `docs/protocol.md` | **High**: design-level issues affect every implementation |
| Verification core (Python) | `agentauth/identity.py`, `crypto.py`, `httpsig.py`, `grants.py`, `limits.py`, `witness.py` | **High** |
| TypeScript verifier | `ts/src/*.ts` | **High**: must agree exactly with the Python core |
| Shared test vectors | `test-vectors/`, `scripts/generate_test_vectors.py` | Medium: check they cover the rules |
| SDK and key storage | `agentauth/sdk.py`, `keystore.py`, `cli.py` | Medium |
| Middleware | `agentauth/asgi.py`, `integrations.py`, `audit.py` | Medium |
| Shared-state backends | `agentauth/backends/redis.py` (Lua ledger, nonce cache) | Medium |
| Registry service | `agentauth/server.py`, `store.py`, `ratelimit.py`, `config.py` | Medium |
| Deployment | `Dockerfile`, `docker-compose.yml`, `deploy/`, `.github/workflows/` | Low |

Out of scope: the cryptographic primitives themselves (`cryptography`, WebCrypto),
third-party framework internals, and the hosting environment.

## Where we think the risk is

These are the places we would look first. Probing beyond them is encouraged.

1. **Parser and canonicalization differentials.** Signed data is canonical JSON, and grant payloads must be byte-for-byte canonical. Compare the Python and TypeScript paths (`crypto.canonical_json`, `grants.Grant.decode`, `ts/src/json.ts`, `ts/src/grants.ts`). Look for any input one accepts and the other rejects, or reads differently: Unicode edge cases, number forms, duplicate keys, whitespace, sort order.
2. **Delegation and attenuation.** `GrantVerifier.verify` and `Limits.narrowing_violation`. Can a child link widen anything (scope algebra, audience `"*"`, limits inheritance, depth, time bounds)?
3. **Stateful limits.** `UsageLedger` and the Redis Lua script. Atomicity across links and replicas, refunds, expiry, and charges racing revocation.
4. **Key event log rules.** Pre-rotation, controller binding (`bound_controller_check`), deactivation paths, and fork or rollback detection (`KelPins`, `witness.merge_logs`, `RegistryPool`).
5. **Request authentication.** The `AgentSig` parser, the replay window and nonce TTL arithmetic, the raw-target handling in middleware and behind proxies, and Host binding.
6. **Key custody.** Crash-safe rotation (`rotate_and_save`), key file handling (planted files, permissions, the encryption format), and the CLI flows.
7. **Middleware semantics.** The path seen by rules versus the path the app routes on, WebSocket and lifespan handling, MCP session binding, and audit-on-deny.
8. **Registry robustness.** Input limits, rate limiting, transaction boundaries (`store.append` preconditions), and error mapping (no 500s on hostile input).

## Known limitations (not findings, unless worse than stated)

These are documented in the [threat model](threat-model.md#known-gaps-v04):

- split views against a client that only talks to one registry;
- no proof of non-revocation;
- caching delays revocation and deactivation;
- per-process defaults unless Redis is configured;
- services must declare costs honestly;
- rate limiting fails open;
- multi-audience budgets are per ledger;
- long-lived connections aren't re-checked;
- the request signature doesn't cover `did` (only an issue when one key serves two DIDs).

## What has already been done

- **Internal review.** An internal review (not independent) in October 2026 produced 41 findings, all high and medium fixed: [security-audit-2026-10.md](security-audit-2026-10.md). Each fix has a regression test (`tests/test_security_audit_2026_10.py`) or a shared test vector.
- **Tests.** Adversarial, fuzz and concurrency tests (`tests/test_grants_adversarial.py`, `test_protocol_hardening.py`, `test_concurrency.py`), plus Redis and PostgreSQL integration and end-to-end tests with real server processes.
- **Static analysis and dependency checks.** ruff, mypy, bandit, CodeQL and pip-audit run in CI. Dependencies are hash-locked, and the lock is checked against `pyproject.toml`.

## Practicalities

- **Getting started.** `pip install -e ".[dev]"`, then `pytest`. Set `AGENTAUTH_TEST_REDIS_URL` and `AGENTAUTH_TEST_POSTGRES_URL` to include the backends. For TypeScript: `cd ts && npm ci && npm test`.
- **Running a registry.** `docker compose up` (see [operations](operations.md)), or `agentauth serve` for a single process.
- **Test vectors.** `python scripts/generate_test_vectors.py` regenerates them, and `--check` verifies they are current.
- **Reporting.** Send findings through GitHub private vulnerability reporting ([SECURITY.md](../SECURITY.md)). We will publish the audit report, with the auditor's agreement, alongside the fixes.

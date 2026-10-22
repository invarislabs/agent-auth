# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [semantic versioning](https://semver.org/) (pre-1.0: minor releases may change formats, and will say so).

## [0.4.0] — unreleased

Production hardening. **Wire formats and version strings are unchanged**; everything a v0.3 client produces is still accepted. Verification is stricter: malformed input that v0.3 accepted by accident is now rejected (see [protocol §9](docs/protocol.md#9-changes-in-v04)).

### Security fixes

- **FastAPI integration verified the decoded path.** Requests to URLs containing percent-encoding (`%20`, `%2F`, …) always failed signature verification. Verification now uses the raw request target.
- **Duplicate `AgentSig` parameters** were silently resolved to the last one. They now invalidate the header.
- **Non-canonical base64url** (padding, stray characters, non-zero trailing bits) was accepted for signatures and grant bodies, so one signature had many spellings. Now rejected.
- **Unknown fields** in events, grants and revocations were ignored; a future constraint would have been silently dropped. Now rejected (fail closed).
- **Crash during rotation lost the new recovery key**, leaving an identity that could never rotate or self-deactivate again. Rotation now persists the next key first and resumes (`AgentIdentity.rotate_and_save`, `agentauth rotate`).
- **`commit()` trusted the registry blindly**: if the registry dropped a submitted rotation, the SDK still swapped keys. It now requires the event in the replayed log.
- **Key files were written through a predictable `<file>.tmp`** opened with `O_TRUNC`, which followed a pre-planted symlink. Temp files are now random, `O_EXCL|O_NOFOLLOW`, fsynced, and the directory is fsynced.
- **`refund()` could return more than was charged**, minting budget. It's now capped.
- **Registry crashes (500) on crafted input**: floats in `meta`, non-string keys, malformed `controller_proof`, lone surrogates, wrong JSON types. All now 400.
- **`/v1/revocations/check` validated input with `assert`**, which `python -O` strips.
- **SQLite store shared one connection across threads without locking reads**, so readers could observe another thread's uncommitted transaction.
- **DIDs were interpolated into registry URLs unvalidated** (path injection into other endpoints). The client and server now require well-formed DIDs.
- **Request bodies were read fully before the size check.** Oversized bodies are now refused before they're read.
- **Forced key refreshes** (a caller presenting a newer `kid`) could be used to make a service fetch from the registry on every request. Now limited to one per DID per second.
- **Infrastructure failures surfaced as 500s** (or, for custom callbacks, propagated unpredictably). Every dependency failure during verification now fails closed with 503.

### Fixed during pre-release review

- A replay cache with a TTL shorter than the replay window (e.g. `max_skew=600` with the default 241 s Redis TTL) allowed replays after the nonce expired. `RequestVerifier` now refuses such a configuration.
- In a `RegistryPool`, one registry sending a junk revocation proof could mask a valid proof from another. All proofs are now checked.
- A network error from one pool member aborted writes that others had accepted, and `sync` crashed when a member was down.
- A crash between writing the current-key and recovery-key files left `rotate_and_save` unable to resume.
- Concurrent key resolution during a rotation could raise a false equivocation alarm (and, in a narrow interleaving, cache stale state). Resolution is now serialized per DID.
- Crafted input could still cause 500s: lone surrogates or NUL bytes in revocation checks and paging cursors, `meta` nested hundreds of levels deep, deeply nested JSON sent to the MCP middleware.
- Several processes opening a fresh SQLite database at once could both apply a migration, or fail with "database is locked".
- A failed audit write after a successful charge returned 500 without refunding. It now refunds and returns 503.
- The in-memory rate limiter reset every client's counters when its key table filled up; it now evicts the least recently seen clients.
- New opt-in `RequestVerifier(bind_host=True)` ties the signed audience to the `Host` header, for apps serving several audiences.

### Added

- **Redis backends** (`agentauth[redis]`): `RedisNonceCache` (atomic `SET NX`) and `RedisUsageLedger` (all-or-nothing check-and-charge in one Lua script), tested across separate processes.
- **PostgreSQL store** (`agentauth[postgres]`) for several registry replicas; **schema migrations** (`agentauth db migrate|status|verify`), upgrade from v0.3 SQLite databases, refusal of newer schemas, and a full **integrity check** that replays every log.
- **Registry operations:** validated environment configuration (`AGENTAUTH_*`), body-size limit, per-address rate limits (memory or Redis), optional registration token, `/readyz`, Prometheus `/metrics`, `/v1/info`, JSON logs with request ids, pagination (`GET /v1/identities`, `?after=&limit=` on `/agents`).
- **Dishonest-registry defences:** log pinning in `RegistryKeyResolver` (`KelPins`, persistent `SQLitePins`) detects rollback and forks; `RegistryPool` writes to and cross-checks several registries; `agentauth sync`; `--registry a,b` in the CLI.
- **Revocation proofs:** `/v1/revocations/check` returns the signed revocations; `RegistryRevocationChecker` verifies them against the issuer's key history (`on_unproven="deny"|"ignore"`).
- **Audit log** (`AuditLog`): hash-chained, optionally signed record of authorization decisions; `fastapi_authorizer(..., audit=)`; `agentauth audit`.
- **ASGI middleware** (`agentauth.asgi.AgentAuthMiddleware`) for any framework, and **MCP** support (`mcp_rules`: per-tool scopes), tested with the official MCP Python SDK (server and client).
- **`Signer` interface** so keys can live in an HSM/KMS; `prepare_rotation(new_next=...)`.
- `AgentIdentity.headers()`, `AgentIdentity.refresh()`, `RegistryClient.info()/list_identities()/revocation_proofs()/submit_revocation()`, retries for idempotent reads.
- Usage ledger pruning of expired grants; bounded in-memory replay cache (refuses rather than forgets when full).
- **Deployment:** `Dockerfile` (hash-locked dependencies, non-root, healthcheck), `docker-compose.yml` (PostgreSQL, Redis, migration job), `.env.example`, `deploy/requirements.lock`.
- **CI:** Python 3.10–3.14 with Redis and PostgreSQL services and coverage gate, minimum-dependency job, httpx-only job, ruff, mypy, pip-audit, bandit, CodeQL, package build and wheel smoke test, Docker build and smoke test, Dependabot.
- ~200 new tests: adversarial/fuzz, concurrency (threads and processes), Redis, PostgreSQL, CLI, MCP and end-to-end with real server processes.

### Changed

- `agentauth serve` reads `AGENTAUTH_*` settings, accepts `--workers`, and refuses `--workers > 1` without Redis.
- Registry rate limits are **on by default** (60 writes and 1200 reads per minute per address).
- New key files use scrypt N=2¹⁷ and record their KDF parameters (v0.3 files still load).
- Nonces must be 16–128 characters; `ts` must be plain digits; grants may not be issued to their own issuer or repeat a link.
- `AuthorizedAgent.charged` accumulates over several `enforce()` calls.
- Python 3.14 added to supported versions.

## [0.3.0]

Resource, spend, rate and use limits on grants; shared counters across delegation chains; refunds; fail-closed resource checks; path-traversal protection; httpx2 compatibility; CI on Python 3.10–3.13.

## [0.2.0]

Scoped capability grants, delegation chains with attenuation, root policies, revocation and cascading deactivation.

## [0.1.0]

Self-certifying `did:agent:` identities, key event logs with pre-rotation, controllers, signed requests, encrypted split key files, registry, SDK and CLI.

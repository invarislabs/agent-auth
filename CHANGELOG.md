# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [semantic versioning](https://semver.org/) (pre-1.0: minor releases may change formats, and will say so).

## [0.4.0] — 2026-10-28

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

### Internal security review (October 2026)

An internal review of the protocol core, registry and SDK (**not an independent audit**; see [docs/security-audit-2026-10.md](docs/security-audit-2026-10.md) for all 41 findings). Every high and medium finding is fixed, each with a regression test or shared test vector.

- **Controller signatures are bound to the controller's keys** when clients replay logs (`bound_controller_check` in `RegistryClient`, `RegistryKeyResolver` and `RegistryPool`). Before, anyone serving logs could append a "controller deactivation" signed by any key. `RegistryPool` also ignores members serving invalid logs instead of letting the longest one win.
- **A planted pending-rotation key file is never adopted.** A pending key the registry hasn't committed to is reused only from an authenticated (v2-encrypted) file. Unencrypted ones are moved aside, not deleted. Plaintext key files are refused when a passphrase is set. New key files (`scrypt-aes256gcm-v2`) bind DID, role and public key into the encryption, and only known scrypt parameter sets are accepted.
- **`AgentAuthMiddleware` checks WebSocket handshakes** (close 1008 unless signed or PUBLIC) and refuses unknown ASGI scope types. Rules see the route path under a mount (`req.path`; `req.full_path` keeps the prefix). MCP sessions are bound to the agent that opened them. Duplicate `Authorization`/`Host`/`AgentGrant` headers are refused. `scope["user"]` is the authenticated agent.
- **Grant payloads must be exactly canonical JSON** (no duplicate keys, floats or alternative encodings), so two implementations can't read one token differently. Audiences and scopes are ASCII-only, and must be sorted, de-duplicated and (for `aud`) lower-cased. Budget, rate and use limits can't target audience `"*"`.
- **Events are rejected before hashing** if nested deeper than 24 levels or holding integers beyond 2⁵³−1. An inception can't commit to its own key. DEL and C1 control characters are refused in limits.
- **Registry:**
  - Writes run off the event loop, re-check controller keys inside the write transaction, and map database lock/pool errors to 503 with `Retry-After`.
  - Bodies must arrive within 10 s (408).
  - The metric `method` label is bounded.
  - `X-Forwarded-For` lines are joined and must be IP addresses; IPv6 is rate-limited per /64; the Redis rate limiter has a 250 ms budget.
  - Failed SQLite commits roll back.
  - Logs are capped at 10,000 events per identity.
  - `/docs` and `/openapi.json` are off, and placeholder (`CHANGE-ME`) secrets are refused.
- **CLI and SDK:**
  - `agentauth init` never overwrites existing key files and saves keys before registering.
  - Concurrent rotations of one identity are refused.
  - Audit records sanitize hostile strings.
  - `controlled_agents` pagination is bounded.
  - `NonceCache` caps live nonces per agent.
  - `refund()` is thread-safe.
- **Supply chain and deployment:**
  - The Docker build installs its build backend from the hashed lock (`--no-build-isolation --no-index`), and CI checks the lock against `pyproject.toml`. The lock is regenerated (fastapi 0.162.0).
  - Compose binds the registry to 127.0.0.1, keeps the Redis password off the command line, and sets memory limits.

**Compatibility:** grants from the reference SDK still verify, unless they use non-ASCII audiences or scopes, or stateful limits on audience `"*"`. A rotation interrupted before reaching the registry restarts with a fresh key if its pending file was unencrypted.

### Added: TypeScript verifier and shared test vectors

- **`ts/`**: `@invarislabs/agentauth`, a zero-dependency TypeScript verifier (WebCrypto) for key event logs, `AgentSig` requests, `AgentGrant` chains, limits and revocation proofs, with a registry client that binds controller keys, pins logs and refuses redirects. See [ts/README.md](ts/README.md).
- **`test-vectors/`**: deterministic cross-implementation vectors generated from the Python reference (`scripts/generate_test_vectors.py`, `--check` in CI). Python (`tests/test_vectors.py`) and TypeScript both run them.
- CI job for the TypeScript verifier; Dependabot for `ts/`.

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
- **Published on PyPI as `invaris-agentauth`.** The name `agentauth` on PyPI belongs to an unrelated project. The import name (`import agentauth`) and the `agentauth` command are unchanged. Install with `pip install invaris-agentauth`, plus extras as before (`invaris-agentauth[server,redis,postgres]`).
- **Release automation.** Publishing a GitHub release builds and checks the package, publishes it to PyPI through trusted publishing (no stored token), and pushes the registry image to `ghcr.io/invarislabs/agent-auth` tagged with the version and `latest`.
- `agentauth serve` reads `AGENTAUTH_*` settings, accepts `--workers`, and refuses `--workers > 1` without Redis.
- Registry rate limits are **on by default** (60 writes and 1200 reads per minute per address).
- New key files use scrypt N=2¹⁷ and record their KDF parameters (v0.3 files still load).
- Nonces must be 16–128 characters; `ts` must be plain digits; grants may not be issued to their own issuer or repeat a link.
- `AuthorizedAgent.charged` accumulates over several `enforce()` calls.
- Python 3.14 added to supported versions.
- Minimum dependency versions raised: `cryptography>=50.0.2`, and for the extras `uvicorn>=0.54.0`, `redis>=8.1.0`, `psycopg>=3.3.6` and `psycopg-pool>=3.3.3` (the versions the lock already pins, tested by the minimum-versions CI job).
- TypeScript verifier builds with TypeScript 7 (`types: ["node"]` is now explicit in `ts/tsconfig.json`, since TypeScript 6+ no longer includes `@types/*` packages automatically).

## [0.3.0]

Resource, spend, rate and use limits on grants; shared counters across delegation chains; refunds; fail-closed resource checks; path-traversal protection; httpx2 compatibility; CI on Python 3.10–3.13.

## [0.2.0]

Scoped capability grants, delegation chains with attenuation, root policies, revocation and cascading deactivation.

## [0.1.0]

Self-certifying `did:agent:` identities, key event logs with pre-rotation, controllers, signed requests, encrypted split key files, registry, SDK and CLI.

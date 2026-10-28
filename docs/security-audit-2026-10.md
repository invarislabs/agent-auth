# Internal security review, October 2026

> **This is not an independent audit.** The maintainers carried out this review of
> their own code, with AI-assisted analysis. Nobody outside the project has checked
> it. Treat it as an extra layer of testing, not as assurance. An external audit is
> still planned before 1.0 ([audit-brief.md](audit-brief.md)).

| | |
|---|---|
| Date | October 2026 |
| Code reviewed | `main` at `f4502ae` (v0.4.0, unreleased), plus the fixes on `feat/security-audit-and-ts-verifier` |
| Scope | Protocol core, registry service and deployment, SDK, ASGI/MCP middleware, CLI and key storage. The new TypeScript verifier was reviewed for differences from the Python reference. |
| Out of scope | Third-party dependencies (they were scanned with tools, not reviewed), the host OS, TLS termination, and cryptographic primitives (Ed25519 and SHA-256 come from `cryptography` / WebCrypto) |
| Result | 41 findings: 3 high, 14 medium, 21 low, 3 informational. Every high and medium finding is fixed. One low finding (S10) is documented for Python and fixed in the TypeScript client. One informational item (R11) is an accepted risk, and the others are documented. |

## Method

The review ran in three parallel passes, one per area. Each pass read the code with
the [threat model](threat-model.md) and the [protocol](protocol.md) at hand, and asked
two questions: what an attacker in each role can reach, and where two components (or
two implementations) might read the same input differently.

| Pass | Covered |
|------|---------|
| **Core** | `identity`, `crypto`, `httpsig`, `grants`, `limits`, `witness`, and the verification paths in `sdk` |
| **Registry** | `server`, `store`, `ratelimit`, `config`, `observability`, `Dockerfile`, `docker-compose.yml`, `.env.example`, `deploy/requirements.lock` and CI |
| **SDK** | `sdk`, `keystore`, `cli`, `asgi`, `integrations`, `audit`, Redis backends |

Writing the TypeScript verifier was a fourth check. Porting every rule meant restating
it exactly, and that surfaced the parser and string-semantics differences in the
"Port" findings below. Both implementations now run the same test vectors
(`test-vectors/`), including vectors for every core finding.

A separate review pass then examined the fixes themselves. It found four problems in them, all corrected before this report:

- a duplicate `Mcp-Session-Id` header could slip past the S4 session check;
- the session check ran after the grant had been charged;
- the first S1 fix could delete a pending key that a lagging registry read had hidden;
- the R10 precondition took a second PostgreSQL pool connection inside the transaction.

It also confirmed that the TypeScript port matches Python check for check, including Python's whitespace definition over every Unicode code point.

Tools run on the result:

| Tool | Result |
|------|--------|
| `ruff` | clean |
| `mypy` | clean |
| `bandit -r agentauth` | no issues |
| `pip-audit` (on `deploy/requirements.lock`) | no known vulnerabilities |
| `npm audit` (`ts/`, dev dependencies only) | 0 vulnerabilities |
| Full test suite | 462 passed, no skips, with Redis and PostgreSQL |
| TypeScript suite | 121 passed |

Severity is judged for a typical deployment: one or more registries, services that
verify requests, and agents with keys on disk.

- **High:** an attacker gains authority or key control they shouldn't have.
- **Medium:** bypass under realistic conditions, cross-implementation disagreement on signed data, or cheap denial of service.
- **Low:** needs unusual conditions, or the impact is limited.
- **Info:** hardening or documentation.

## Findings

Status: **Fixed** means changed in code and covered by a regression test, named in
`tests/test_security_audit_2026_10.py` (prefix R, S or C), in the shared vectors, or
in both. **Documented** means a known limitation, now written down in the threat model.

### Core protocol (C)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| C1 | High | **Controller signatures weren't bound to the controller's keys when a client replayed a log.** `verify_log` with its default check accepted a "controller deactivation" signed by *any* key, as long as it named the controller. Anyone serving logs (a registry, a mirror, one `RegistryPool` member) could append one and deactivate a controlled agent in every client's view. In a pool, the longer forged log also won the merge. | Fixed. `bound_controller_check` requires the key to be in the controller's verified log, and is used by `RegistryClient.verified_state`, `RegistryKeyResolver` and `RegistryPool`. The pool verifies each member's log before merging (`_valid_logs`). Vector: `controller_deactivation_unbound_key`. |
| C2 | Medium | **Grant payloads didn't have to be canonical.** A payload with a duplicate key (`"sub"` twice) or `1.0` for `1` re-canonicalized to the signed bytes in Python, which keeps the last duplicate. A verifier in another language could read a different subject out of the same valid token. | Fixed. The payload must equal `canonical_json(body)` byte for byte. Duplicate keys, floats, unsafe integers and nesting deeper than 8 are refused (400). Vectors: `noncanonical_payload`, `duplicate_key`, `float_in_body`. |
| C3 | Medium | **Audiences were compared with Unicode case folding** (`str.lower()`). Characters such as `İ` or the Kelvin sign fold differently across languages and libraries, so implementations could disagree on whether a grant covers a service. | Fixed. Audiences and scopes are printable ASCII only, and compared ASCII-case-insensitively. Vector: `non_ascii_audience`. |
| C4 | Medium | **Deeply nested events crashed canonicalization** with `RecursionError` (500 from the registry, exception in clients). Integers beyond 2⁵³−1 were accepted, though not every implementation can represent them. | Fixed. Events are checked iteratively before hashing: at most 24 levels, safe integers only. `RecursionError` is mapped to a validation error. Vectors: `event_too_deep`, `inception_unsafe_int`. |
| C5 | Low | **An inception could commit to its own current key** (`next == commitment(key)`). Pre-rotation then protects nothing: stealing the current key also gives the recovery key. | Fixed in verification and in `make_inception`. Vector: `inception_next_equals_key`. |
| C6 | Low | **Budget, rate and use limits on audience `"*"`.** Every service keeps its own ledger, so the limit applied once per service. | Fixed. Refused at issue time (400) and at verification (403). Vector: `stateful_wildcard_audience`. |
| C7 | Low | **`aud` and `scope` order wasn't enforced when verifying**, so one grant had several valid encodings. | Fixed. They must already be sorted, de-duplicated and lower-cased (for `aud`). Vectors: `unsorted_audience`, `uppercase_audience`, `unsorted_scope`. |
| C8 | Low | **DEL and C1 control characters** were allowed in resource patterns, units and requested resources (C0 only was refused). They enable log injection and confusing display. | Fixed. Limits vectors include DEL and NEL. |
| C9 | Low | **The event timestamp regex used `\d`**, which matches non-ASCII digits in Python. | Fixed (`[0-9]`). |
| C10 | Low | **One agent could fill the in-memory replay cache.** Every other agent then got 503 until entries expired. | Fixed. `NonceCache(max_per_did=100_000)`. |
| C11 | Low | **The `Authorization` size limit counted characters, not bytes.** | Fixed. It now counts UTF-8 bytes. |
| C12 | Low | **Concurrent `refund()` calls on one request** could both pass the "not more than charged" check. | Fixed. Refunds are serialized per request. |
| C13 | Info | **`GrantVerifier` without a revocation check** silently accepts revoked grants. | A warning is logged at construction. |

### Registry service and deployment (R)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| R1 | Medium | **Unbounded metric labels.** The HTTP method went into a Prometheus label as sent, so requests with random methods grew memory without limit. | Fixed. Unknown methods are counted as `OTHER`. |
| R2 | Medium | **The Redis rate limiter ran on the event loop.** A slow or hung Redis stalled every request in the worker. | Fixed. It runs in the threadpool with a 250 ms budget, then fails open, which is the documented behaviour. |
| R3 | Medium | **Synchronous database calls in async handlers** blocked the event loop. Lock and pool timeouts surfaced as 500. | Fixed. Write handlers run in the threadpool. Lock, pool and connection errors return 503 with `Retry-After`. |
| R4 | Medium | **`X-Forwarded-For` handling.** Only the first header line was read, and any string was accepted as a client address, so junk values minted fresh rate-limit keys. Compose also published port 8000 on every interface. | Fixed. All lines are joined and the value must be an IP address, else the socket peer is used. Compose binds `127.0.0.1:8000`. |
| R5 | Low | **IPv6 clients could rotate addresses within their /64** to escape per-address limits. Open registration was silent. | Fixed. IPv6 is counted per /64. A warning is logged when registration is open. |
| R6 | Low | **A failed SQLite `COMMIT`** left the shared connection inside a transaction. WAL mode was assumed, not checked. | Fixed. A failed `COMMIT` is rolled back. The registry warns if WAL couldn't be enabled. |
| R7 | Medium | **Slow request bodies.** A client trickling bytes held a worker indefinitely. | Fixed. The body must arrive within 10 s, else 408. |
| R8 | Medium | **Build supply chain.** `pip install .` in the Dockerfile downloaded setuptools without hash checking. The lock pinned `fastapi==0.160.0`, while `pyproject.toml` required `>=0.162.0`, and nothing caught the drift. | Fixed. setuptools is in the hashed lock and the build uses `--no-build-isolation --no-index`. The lock is regenerated, and a CI job fails if it disagrees with `pyproject.toml`. Pinning the base image by digest is documented, not enforced. |
| R9 | Low | **Defaults.** The Redis password was visible on the command line. `CHANGE-ME` placeholders could be deployed as real secrets. `/docs` and `/openapi.json` were public. Compose had no memory limits. 413 responses weren't counted in metrics. | Fixed. The password goes into a config file. The registry refuses to start with placeholder secrets. Docs and OpenAPI are off. Compose has memory limits. 413 and 408 are counted. Using a non-superuser database role is documented in operations. |
| R10 | Low | **Controller check race.** A controlled inception or controller deactivation was checked against the controller's current key outside the write transaction, so a concurrent controller rotation could interleave. | Fixed. The check re-runs inside the transaction, under the controller's write lock (`store.append(precondition=...)`). |
| R11 | Info | **Client-chosen `X-Request-ID`** is echoed back and logged. | Accepted. The format is restricted to 64 characters from `[A-Za-z0-9_.-]`, and the id is only used to correlate logs. |
| R12 | Low | **Unbounded logs.** `GET /v1/identities/{did}/log` returns the whole log, and nothing limited how many events an identity could add. | Fixed. At most 10,000 events per identity. |

### SDK, middleware and key storage (S)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| S1 | High | **A planted `pending.json` was adopted as the next key.** Someone able to write to the recovery directory could drop in a plaintext pending-rotation file with their own key. The next `rotate` committed the identity to it, handing over recovery control. Encrypted files could also be swapped between identities or roles. | Fixed. When the registry hasn't committed to a pending key, it is reused only if its file is authenticated (encrypted in the v2 format under the identity's passphrase). Otherwise the file is moved aside (not deleted, in case a lagging read hid a commit) and a fresh key is used. Plaintext key files are refused when a passphrase is configured. A new encryption format (`scrypt-aes256gcm-v2`) binds DID, role and public key into the AES-GCM associated data, and v0.4 files still load. |
| S2 | High | **WebSockets bypassed the middleware.** `AgentAuthMiddleware` passed every non-HTTP scope straight to the app, so WebSocket routes behind it were unauthenticated. | Fixed. WebSocket handshakes go through `rules` and need a valid signature unless PUBLIC, otherwise the connection is closed with 1008. Lifespan events pass through, and unknown scope types are refused. |
| S3 | Medium | **Rules saw the wrong path under a mount.** Under a `Mount`, `req.path` included the prefix while the app routed without it, so a rule like `path == "/admin"` silently didn't match. | Fixed. `req.path` is relative to the wrapped app and `req.full_path` keeps the prefix. Deny-by-default rules are recommended in the docs. |
| S4 | Medium | **MCP session hijack.** Any authenticated agent presenting another agent's `Mcp-Session-Id` was let through to that session. | Fixed. Sessions are bound to the DID that opened them (403 otherwise). The check runs before any grant is charged or audited, a duplicate session header is refused, and a session is bound only from a response to a request that carried no session id. `scope["user"]` is set to the authenticated agent. The binding is per process; multi-worker deployments need sticky sessions (documented). |
| S5 | Medium | **`agentauth init` could destroy a recovery key.** It checked only the current-key file before writing, so with `--recovery-dir` it could overwrite another identity's recovery key. | Fixed. Every path is checked, and files are created with an atomic create-if-absent (`save(overwrite=False)`). |
| S6 | Medium | **Junk logs from one pool member** could win `RegistryPool`'s merge. | Fixed with C1. |
| S7 | Low | **Hostile strings could make audit writes fail.** A lone surrogate in a client-supplied path or resource made the write fail, so the denial went unrecorded. | Fixed. Strings are sanitized (U+FFFD) and truncated before recording. |
| S8 | Low | **`init` registered before saving keys.** A crash in between left a registered identity with no keys. | Fixed. Keys are saved first. If registration fails, the inception event is kept for `agentauth register`. |
| S9 | Low | **scrypt parameters from key files were loosely capped** (up to N=2²⁰, r=32, p=16). A planted file could make loading burn gigabytes of memory. | Fixed. Only the two parameter sets the library has ever written are accepted. |
| S10 | Low | **Redirects can carry `AgentGrant` to another origin** if a caller enables `follow_redirects`. The grant is useless without the subject's key, and httpx doesn't follow redirects by default. | Documented. The TypeScript registry client refuses redirects. |
| S11 | Low | **Duplicate `Authorization`, `Host` or `AgentGrant` headers** could be read differently by the middleware and the app. | Fixed. They are refused (400). |
| S12 | Low | **Two concurrent `rotate_and_save` calls** could both proceed. | Fixed. The pending file is created exclusively, so a rotation that finds one appearing stops. The registry accepts only one event per sequence number in any case. |
| S13 | Info | **Smaller documented limitations:** pin-store eviction (LRU), WebSocket and SSE connections not re-checked after they open, `mcp_rules` covering `tools/call` only, and unbounded `controlled_agents` pagination. | Documented, and pagination is now bounded. |

### Differences found while porting to TypeScript (P)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| P1 | Medium | **`JSON.parse` loses types.** It turns `1.0` into `1` and rounds integers above 2⁵³, so a JavaScript verifier built on it would accept payloads the protocol forbids. | The TypeScript verifier uses its own strict parser. C2 makes the bytes canonical in both implementations. |
| P2 | Low | **Whitespace means different things.** JavaScript's `\s` includes U+FEFF and excludes U+001C–U+001F and U+0085, unlike Python's `str.isspace()`, so the two disagreed on which resource patterns are valid. | TypeScript reproduces Python's definition (`ts/src/pystr.ts`). Vector added. |
| P3 | Low | **Sort order differs.** JavaScript's default string comparison orders by UTF-16 code unit, while Python orders by code point. They differ for characters above U+FFFF. | TypeScript sorts by code point. Vector added. |

## What changed for users

These changes reject input that v0.4.0 previews accepted. For every one, a grant or
event produced by the reference SDK still verifies, except in the cases noted.

- **Grant payloads must be canonical.** The SDK always produced canonical payloads.
- **Audiences and scopes must be printable ASCII.** Grants with non-ASCII audiences or scopes must be re-issued.
- **No budget, rate or use limits on audience `"*"`.** List the audiences explicitly instead.
- **New key files use `scrypt-aes256gcm-v2`.** Old files still load.
- **Plaintext key files are refused when a passphrase is set.** Re-save them encrypted, or unset the passphrase.
- **An interrupted rotation reuses its saved key only if that file is encrypted (v2).** An unencrypted pending file is moved aside and a fresh key is used.
- **`AgentAuthMiddleware` checks WebSocket handshakes and refuses unknown scope types.** `req.path` excludes the mount prefix, and duplicate security headers are refused.
- **The registry no longer serves `/docs` or `/openapi.json`, and refuses to start with `CHANGE-ME` secrets.** Compose binds to loopback.

## Not covered

An external auditor should spend time on what this review left out:

- **Formal analysis of the protocol.** It was checked by reading, not modelled.
- **Side channels** beyond what the threat model already states.
- **Cryptographic library correctness.**
- **Load testing** of the registry under adversarial traffic.
- **Dependency source review** and the CI/CD pipeline's own security, such as branch protection and action pinning by SHA.
- **Fuzzing the TypeScript verifier.** The vectors exercise it, but it hasn't been fuzzed.

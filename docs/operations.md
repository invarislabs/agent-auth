# Operations

How to deploy the registry, run relying services safely at scale, and manage keys.

- [Deployment options](#deployment-options)
- [Configuration](#configuration)
- [Database and migrations](#database-and-migrations)
- [Health, metrics and logs](#health-metrics-and-logs)
- [Scaling](#scaling)
- [Behind a reverse proxy](#behind-a-reverse-proxy)
- [Backups and integrity](#backups-and-integrity)
- [Key management](#key-management)
- [Incident response](#incident-response)
- [Upgrading](#upgrading)

## Deployment options

| Setup | Database | Shared state | Use it for |
|---|---|---|---|
| `agentauth serve` | SQLite file | none (one process) | development, pilots, small single-host installs |
| `docker compose up` (this repo) | PostgreSQL | Redis | a complete production-shaped stack on one host |
| Your orchestrator, image from `Dockerfile` | PostgreSQL | Redis | several registry replicas behind a load balancer |

### Single process

```bash
pip install "agentauth[server]"
agentauth db migrate --database-url sqlite:////var/lib/agentauth/agentauth.db
AGENTAUTH_DATABASE_URL=sqlite:////var/lib/agentauth/agentauth.db \
AGENTAUTH_AUDIENCES=registry.example.com \
agentauth serve --host 0.0.0.0 --port 8000
```

### Docker Compose (PostgreSQL + Redis)

```bash
cp .env.example .env        # set POSTGRES_PASSWORD, REDIS_PASSWORD, AGENTAUTH_AUDIENCES
docker compose up -d
curl -fsS http://localhost:8000/readyz
```

The compose file runs a one-shot `migrate` job before the registry starts (with `AGENTAUTH_AUTO_MIGRATE=false` on the registry itself), runs the registry with three workers sharing Redis, persists Redis with AOF, and runs the registry container read-only, as a non-root user, with all capabilities dropped.

### The image

`Dockerfile` builds a two-stage image: dependencies are installed from `deploy/requirements.lock` **with hash checking**, the app runs as UID 10001, data lives in `/data`, and the container healthcheck calls `/readyz`. For bit-for-bit reproducible builds, also pin the base image by digest; Dependabot is configured to keep it current.

```bash
docker build -t agentauth-registry .
docker run -p 8000:8000 -e AGENTAUTH_AUDIENCES=localhost:8000 -v agentauth-data:/data agentauth-registry
docker run --rm -e AGENTAUTH_DATABASE_URL=... agentauth-registry db migrate     # any CLI command works
```

Regenerate the lock after changing dependencies:

```bash
uv pip compile pyproject.toml --extra server --extra redis --extra postgres \
   --python-version 3.12 --universal --generate-hashes -o deploy/requirements.lock
```

## Configuration

The registry reads `AGENTAUTH_*` variables at startup and **refuses to start** on an invalid value. `.env.example` lists them all.

| Variable | Default | Meaning |
|---|---|---|
| `AGENTAUTH_DATABASE_URL` | `agentauth.db` | `sqlite:///relative.db`, `sqlite:////absolute.db`, a bare path, or `postgresql://user:pass@host/db`. (`AGENTAUTH_DB`, the v0.3 name, still works.) |
| `AGENTAUTH_AUDIENCES` | `localhost:8000,127.0.0.1:8000` | Comma-separated `host[:port]` values clients use to reach the registry (for `/v1/whoami`) |
| `AGENTAUTH_AUTO_MIGRATE` | `true` | Apply schema migrations at startup. Set `false` in production and run `agentauth db migrate` as a deployment step. |
| `AGENTAUTH_REDIS_URL` | unset | Shared replay cache and rate limits. **Required** for more than one worker or replica. |
| `AGENTAUTH_RATE_LIMIT_WRITES` | `60/60` | Per client address: `COUNT/SECONDS`, or `off` |
| `AGENTAUTH_RATE_LIMIT_READS` | `1200/60` | Same, for reads (including revocation checks). Relying services resolve through the registry, so size this for your services' cache misses, or exempt their addresses at the proxy. |
| `AGENTAUTH_TRUSTED_PROXY_HOPS` | `0` | How many proxies' `X-Forwarded-For` entries to trust for the client address. `0` ignores the header (it's client-controlled). |
| `AGENTAUTH_REGISTRATION_TOKEN` / `_FILE` | unset | If set (≥ 16 characters), `POST /v1/identities` needs header `X-AgentAuth-Registration-Token`. Use `_FILE` with a secret mount. |
| `AGENTAUTH_MAX_BODY_BYTES` | `16384` | Larger request bodies get `413` before they're read |
| `AGENTAUTH_MAX_SKEW` | `120` | Allowed clock skew for signed requests to the registry |
| `AGENTAUTH_RESOLVE_CACHE_SECONDS` | `30` | `Cache-Control: max-age` on DID resolution |
| `AGENTAUTH_METRICS` | `true` | Serve `/metrics` |
| `AGENTAUTH_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `AGENTAUTH_LOG_FORMAT` | `json` | `json` (one object per line) or `text` |

For the CLI and SDK:

| Variable | Default | Meaning |
|---|---|---|
| `AGENTAUTH_REGISTRY` | `http://127.0.0.1:8000` | Registry URL, or several comma-separated URLs to cross-check |
| `AGENTAUTH_HOME` | `~/.agentauth` | Where key files live |
| `AGENTAUTH_PASSPHRASE` / `_PASSPHRASE_FILE` | unset | Encrypts key files when saving, decrypts when loading. The CLI warns when it writes unencrypted keys. |
| `AGENTAUTH_REGISTRATION_TOKEN` | unset | Sent when registering identities |

## Database and migrations

The schema is versioned in a `schema_migrations` table.

```bash
agentauth db status   --database-url "$AGENTAUTH_DATABASE_URL"   # current vs expected version, pending migrations
agentauth db migrate  --database-url "$AGENTAUTH_DATABASE_URL"   # apply pending migrations (idempotent)
agentauth db verify   --database-url "$AGENTAUTH_DATABASE_URL"   # replay every log; exit 1 on any inconsistency
```

- A v0.3 SQLite database is recognised and upgraded in place (its tables become migration 1).
- A database whose schema is **newer** than the running code is refused, so a rollback to an older binary can't write to a schema it doesn't understand.
- With PostgreSQL, concurrent `migrate` runs (several replicas starting at once) are serialized with an advisory lock.
- `/readyz` returns 503 until the schema is current.

| Table | Contents | Loss impact |
|---|---|---|
| `events` | Every signed event, the source of truth | **Critical.** Identities become unresolvable. The events are self-verifying, so they can be re-imported from any copy (`agentauth sync` from another registry). |
| `identities` | State derived from `events`, plus a controller index | Rebuildable by replaying `events` |
| `revocations` | Signed grant revocations | **Critical.** Revoked grants would come back to life. |
| `schema_migrations` | Applied migrations | Recreated by `db migrate` |

SQLite runs in WAL mode with `synchronous=FULL` (a committed revocation survives power loss) and a busy timeout, so several worker processes on one host can share the file. PostgreSQL serializes writers per DID with an advisory lock, and the `(did, seq)` primary key is the final arbiter of concurrent appends.

## Health, metrics and logs

| Endpoint | Use |
|---|---|
| `GET /healthz` | Liveness: the process answers |
| `GET /readyz` | Readiness: the database answers, the schema is current, Redis (if configured) answers. 503 otherwise. |
| `GET /metrics` | Prometheus text format. Restrict access at the proxy if you don't want it public. |
| `GET /v1/info` | Version, protocol versions, schema version, registration mode |

Metrics:

| Metric | Labels | Watch for |
|---|---|---|
| `agentauth_http_requests_total` | `method`, `route`, `status` | 5xx; spikes of 401 |
| `agentauth_http_request_duration_seconds` | `route` | latency (histogram) |
| `agentauth_registry_events_total` | `type`, `outcome` (`accepted`, `invalid`, `conflict`, `unauthorized`) | bursts of `invalid` (probing) or `conflict` (racing writers) |
| `agentauth_registry_revocations_total` | `outcome` | |
| `agentauth_http_rate_limited_total` | `kind` | sustained limiting: raise limits or find the client |
| `agentauth_registry_identities`, `…_active_identities`, `…_stored_revocations` | — | growth |
| `agentauth_build_info` | `version` | |

Logs are JSON lines on stdout (`AGENTAUTH_LOG_FORMAT=json`): one `request` entry per call (request id, method, path, route, status, client, duration) plus events such as `identity registered`, `key event accepted` and `grant revoked`. The startup line logs the effective configuration with passwords redacted. Every response carries `X-Request-ID`; pass your own to correlate.

On **relying services**, alert on:

- `agentauth.sdk` CRITICAL `registry equivocation detected` — a registry served a log inconsistent with one this service verified before. Treat as a security incident (see below).
- `agentauth.sdk` WARNING `claims … is revoked without a valid proof` — a registry reported a revocation it couldn't prove.
- 503 responses from your endpoints — the registry, Redis or your policy store is unreachable, and AgentAuth is failing closed.

## Scaling

### Shared state

Anything that runs more than one process verifying requests for the same audience — uvicorn/gunicorn workers count — needs shared state:

| State | Default | Problem with more than one process | Use |
|---|---|---|---|
| Replay cache | `NonceCache` (in memory) | A request can be replayed once per process | `agentauth.backends.redis.RedisNonceCache` |
| Usage ledger | `UsageLedger` (in memory) | Budgets, rates and uses counted per process: N× the limit | `agentauth.backends.redis.RedisUsageLedger` |
| Key and revocation caches | in memory | None: they only affect freshness | nothing |
| Log pins | `KelPins` (in memory) | Each process detects rollback on its own; a restart forgets | `SQLitePins(path)` per host, if you want detection to survive restarts |
| Registry rate limits | in memory | Limits apply per process | set `AGENTAUTH_REDIS_URL` |

```python
from agentauth.backends.redis import RedisNonceCache, RedisUsageLedger

RequestVerifier(keys, audiences={"api.example.com"}, nonce_cache=RedisNonceCache(REDIS_URL))
GrantVerifier(keys, root_policy=..., ledger=RedisUsageLedger(REDIS_URL))
```

The Redis ledger checks and charges every link of a chain in one Lua script, so the all-or-nothing guarantee holds across replicas. Counters expire with their grants. Use Redis ≥ 6 (standalone, Sentinel or a managed primary; **not** Redis Cluster), enable AOF persistence if budgets must survive a Redis restart, and keep Redis private. If Redis is unreachable, requests are refused with 503.

`agentauth serve --workers N` refuses to start without `AGENTAUTH_REDIS_URL`. If you start the registry another way (`uvicorn agentauth.server:get_app --factory --workers N`, gunicorn), you must set it yourself.

### Registry replicas

With PostgreSQL and Redis, any number of registry replicas can run behind a load balancer. SQLite supports several workers on one host but not several hosts.

### Several independent registries

For protection against a dishonest registry operator, run (or federate with) independent registries and point clients at all of them:

```bash
export AGENTAUTH_REGISTRY=https://reg-a.example.com,https://reg-b.example.org
agentauth init researcher            # registered at both
agentauth sync did:agent:…           # copy events a lagging registry is missing
```

```python
from agentauth import RegistryClient, RegistryPool, RegistryKeyResolver
pool = RegistryPool([RegistryClient("https://reg-a.example.com"), RegistryClient("https://reg-b.example.org")])
keys = RegistryKeyResolver(pool, ttl=30)
```

Reads require every registry to answer by default (`read_quorum`); lower it to stay available when one is down, at the cost of fewer registries having to collude.

## Behind a reverse proxy

- **Terminate TLS** at the proxy. AgentAuth doesn't need TLS for its own security, but request bodies and grants may be sensitive.
- **Preserve the request target exactly.** Method, path and query are covered by request signatures, and verification uses the raw (still percent-encoded) path. Don't strip prefixes, normalize slashes or re-encode.
- **Audience = the public `host[:port]`** clients use, not the internal upstream address. On the standard HTTPS port, that's the bare host name.
- **Client addresses.** Set `AGENTAUTH_TRUSTED_PROXY_HOPS` to the number of proxies that append to `X-Forwarded-For`; otherwise every client looks like the proxy to the rate limiter.
- **Limit body sizes** at the proxy too; it's cheaper than reaching the app.

## Backups and integrity

- **PostgreSQL:** your usual tooling (`pg_dump`, PITR). The `events` and `revocations` tables are the ones that matter.
- **SQLite:** `sqlite3 agentauth.db ".backup /backups/agentauth-$(date +%F).db"` is safe while running.
- **Test restores**, then run `agentauth db verify` on the restored copy: it replays every log and compares it with the stored state, so it also detects corruption or tampering.
- A wiped registry can be rebuilt from any other copy of the logs (`agentauth sync` with a pool), because events are self-certifying. **Revocations can't** be rebuilt that way; back them up.

## Key management

### For agents

| Key | Lives where | Needed for |
|---|---|---|
| Current key (`<name>.key.json`) | On the agent's host, readable only by the agent process (mode 0600) | Signing every request, issuing grants |
| Recovery key (`<name>.recovery.json`) | **Somewhere else**: an operator's machine, a vault, or an HSM/KMS (any object implementing `Signer`) | Rotation and self-deactivation |
| Pending key (`<name>.pending.json`) | Next to the recovery key, only during a rotation | Finishing an interrupted rotation |

- **Encrypt at rest** with `AGENTAUTH_PASSPHRASE_FILE` pointing at a secret from your secrets manager. New files use scrypt (N=2¹⁷, r=8, p=1) + AES-256-GCM; v0.3 files (N=2¹⁵) still load.
- **Keep the recovery key off the agent host.** This is what makes pre-rotation meaningful.
- **Give important agents a controller.** It's your kill switch if both keys are lost.

### For principals (humans and orgs)

A principal's key sits at the root of many grant chains, so protect it more carefully than any agent's:

- Keep it on a workstation, in a vault or in an HSM, never on agent infrastructure.
- Issue short-lived grants (minutes to hours), and re-issue them rather than extending them.
- Rotating a principal invalidates every grant it issued. Plan rotations, or treat them as an emergency "revoke everything".

### Routine rotation

```bash
agentauth --recovery-dir /secure/vault rotate researcher
```

This writes the new next key to `/secure/vault/researcher.pending.json`, submits the rotation, replays the registry's log to confirm it, rewrites the key files and removes the pending file. If anything fails in between, run the same command again: it detects the pending file, checks what the registry has, and completes or retries the same rotation. Afterwards:

- Services refresh automatically when they see the new `kid`.
- Grants this agent **issued** must be re-issued. Grants it **holds** are unaffected.

## Incident response

| Situation | Action |
|---|---|
| Agent's current key may be exposed | `rotate`, then re-issue any grants it issued |
| Agent is misbehaving | Revoke the grants it holds (`agentauth revoke <issuer> <grant-id>`), or deactivate it as its controller (`agentauth deactivate <did> --as <controller>`) |
| Both of an agent's keys may be exposed | Deactivate it as its controller. Create a new identity and issue new grants. |
| A principal's key may be exposed | Rotate the principal (this invalidates all its grants), then re-issue what's needed |
| **Equivocation detected** (`EquivocationError`, 503s naming a DID) | Requests for that DID fail closed until resolved. Collect the evidence logged with the error (both digests). A fork at a rotation means that identity's recovery key signed two rotations: treat the identity as compromised and deactivate it via its controller. A rollback means a registry is withholding events: stop trusting that registry and compare `agentauth log <did>` across registries. To clear a pin after investigation, delete the DID's row from the pin store. |
| Registry database restored from an old backup | Clients with pins will report rollback for identities that changed since. Re-sync missing events from another registry or from agents' own records (`agentauth sync`), then verify with `agentauth db verify`. |

Deactivation is permanent. A deactivated DID can never be reused.

## Upgrading

### From v0.3 to v0.4

- **Wire formats are unchanged.** v0.3 agents work against v0.4 services and registries. Verification is stricter (see [protocol §9](protocol.md#9-changes-in-v04)); only malformed input that v0.3 accepted by accident is now refused.
- **Registry:** take a backup, then `agentauth db migrate` (or let `AGENTAUTH_AUTO_MIGRATE` do it). `--db` and `AGENTAUTH_DB` still work. Rate limits are now **on by default**; review `AGENTAUTH_RATE_LIMIT_READS` if many services resolve through your registry.
- **Services:** if you run more than one process, switch to the Redis backends. Custom ledgers written for v0.3 (no `expires_at` keyword) still work. `RegistryRevocationChecker` now verifies revocation proofs; against a v0.3 registry (no proofs) its default `on_unproven="deny"` behaves exactly like v0.3.
- **FastAPI services:** requests to percent-encoded URLs now verify (they failed in v0.3).
- **Agents:** use `identity.rotate_and_save(...)` (what the CLI's `rotate` now does) instead of `registry.rotate()` followed by `save()`.
- **Python:** 3.10–3.14.

Formats are versioned (`agentauth/1`, `agentauth-grant/1`, …). Until 1.0, minor releases may change them; the changelog will say so, and relying services and agents should then be upgraded together.

# Operations

How to run the registry and manage keys. AgentAuth v0.3 is suitable for development, internal pilots and single-instance deployments. Read [Scaling](#scaling) before running more than one replica.

## Running the registry

### With the CLI

```bash
pip install "agentauth[server]"
agentauth serve --host 0.0.0.0 --port 8000 --db /var/lib/agentauth/agentauth.db \
                --audience registry.example.com
```

`--audience` (repeatable) lists the `host[:port]` values clients use to reach the registry. The CLI always adds `<host>:<port>`, `localhost:<port>` and `127.0.0.1:<port>`. Behind a proxy on the standard HTTPS port, clients sign for `registry.example.com` with no port, so list exactly that.

### With uvicorn (or any ASGI server)

```bash
AGENTAUTH_DB=/var/lib/agentauth/agentauth.db \
AGENTAUTH_AUDIENCES=registry.example.com \
uvicorn agentauth.server:get_app --factory --host 0.0.0.0 --port 8000
```

### Configuration

| Variable | Used by | Default | Meaning |
|---|---|---|---|
| `AGENTAUTH_DB` | registry (`create_app`) | `agentauth.db` | SQLite database path |
| `AGENTAUTH_AUDIENCES` | registry (`create_app`, not `agentauth serve`) | `localhost:8000,127.0.0.1:8000` | Comma-separated audiences for authenticated endpoints |
| `AGENTAUTH_REGISTRY` | CLI | `http://127.0.0.1:8000` | Registry URL |
| `AGENTAUTH_HOME` | CLI | `~/.agentauth` | Where key files live |
| `AGENTAUTH_PASSPHRASE` | SDK and CLI | unset | Encrypts key files when saving and decrypts them when loading |

### Behind a reverse proxy

- **Terminate TLS** at the proxy. AgentAuth doesn't need TLS for its own security, but request bodies and grants may be sensitive.
- **Preserve the path and query exactly.** They're covered by request signatures, so a rewritten path breaks verification.
- **Audience = the public `host[:port]`** clients use, not the internal upstream address.
- **Rate-limit `POST /v1/identities`.** Registration is open by design.
- **Limit body sizes.** The registry rejects events over 16 KiB, but it's cheaper to stop them at the proxy.

### Health and monitoring

- `GET /healthz` returns `{"ok": true}`.
- Track the rates of 401/403/402/429 responses on relying services. Spikes in 401 "replayed" or "signature" errors can mean an attack, or a proxy mangling requests.

## Data and backups

The registry's SQLite database has three tables:

| Table | Contents | Loss impact |
|---|---|---|
| `events` | Every signed event, the source of truth | **Critical.** Identities become unresolvable. The events are self-verifying, so they can be re-imported from any copy. |
| `identities` | State derived from `events`, plus a controller index | Can be rebuilt by replaying `events` |
| `revocations` | Signed grant revocations | **Critical.** Revoked grants would come back to life. |

The database uses WAL mode. Back it up with `sqlite3 agentauth.db ".backup /backups/agentauth-$(date +%F).db"` (safe while running), and test restores.

## Key management

### For agents

| Key | Lives where | Needed for |
|---|---|---|
| Current key (`<name>.key.json`) | On the agent's host, readable only by the agent process (the file is written with mode 0600) | Signing every request, issuing grants |
| Recovery key (`<name>.recovery.json`) | **Somewhere else**: an operator's machine, a vault, or a KMS/HSM-backed store | Rotation and self-deactivation |

- **Encrypt at rest** with `AGENTAUTH_PASSPHRASE`, supplied from your secrets manager, not hard-coded.
- **Keep the recovery key off the agent host.** This is what makes pre-rotation meaningful: if both keys sit in one directory, stealing that directory steals the whole identity.
- **Give important agents a controller.** It's your kill switch if both keys are lost.

### For principals (humans and orgs)

A principal's key sits at the root of many grant chains, so protect it more carefully than any agent's:

- Keep it on a workstation or in a vault, never on agent infrastructure.
- Issue short-lived grants (minutes to hours), and re-issue them rather than extending them.
- Rotating a principal invalidates every grant it issued. Plan rotations, or treat them as an emergency "revoke everything".

### Routine rotation

```bash
agentauth --recovery-dir /secure/vault rotate researcher
```

This reveals the pre-committed key, makes it current, and commits to a fresh next key. The new recovery file is written to `--recovery-dir`. Afterwards:

- Services refresh automatically when they see the new `kid`.
- Grants this agent **issued** must be re-issued. Grants it **holds** are unaffected.

### Incident response

| Situation | Action |
|---|---|
| Agent's current key may be exposed | `rotate`, then re-issue any grants it issued |
| Agent is misbehaving | Revoke the grants it holds (`agentauth revoke <issuer> <grant-id>`), or deactivate it as its controller (`agentauth deactivate <did> --as <controller>`) |
| Both of an agent's keys may be exposed | Deactivate it as its controller. Create a new identity and issue new grants. |
| A principal's key may be exposed | Rotate the principal (this invalidates all its grants), then re-issue what's needed |

Deactivation is permanent. A deactivated DID can never be reused.

## Scaling

v0.3 keeps some state in memory **per process**:

| State | Where | Problem with more than one replica | What to do |
|---|---|---|---|
| Nonce replay cache (`NonceCache`) | Relying services and the registry | A request could be replayed against a different replica within the timestamp window | Implement `check_and_store(did, nonce)` on Redis (`SET key 1 NX EX ttl`) |
| Usage ledger (`UsageLedger`) | Relying services | Budgets, rates and uses are counted per replica, allowing up to N× the limit | Implement `consume`, `refund` and `usage` on Redis (Lua script) or in your database (one transaction) |
| Key and revocation caches | Relying services | Per-replica caches are fine: they only affect freshness | Nothing |
| Registry database | Registry | SQLite is single-node | Run a single registry instance for now. Postgres support is on the [roadmap](roadmap.md). |

Pass your implementations in through the constructors: `RequestVerifier(..., nonce_cache=...)` and `GrantVerifier(..., ledger=...)`.

## Upgrading

The formats are versioned (`agentauth/1`, `agentauth-grant/1`, …; see the [protocol spec](protocol.md#8-version-strings-and-constants)). Until 1.0, minor releases may change them. Check the release notes before upgrading, and upgrade relying services and agents together when a format changes.

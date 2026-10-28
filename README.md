# AgentAuth

[![CI](https://github.com/invarislabs/agent-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/invarislabs/agent-auth/actions/workflows/ci.yml)

Cryptographic identities and delegated authority for autonomous AI agents. Built and maintained by [Invaris Labs](https://www.invarislabs.com/).

> **Status (v0.4):** hardened for production use — shared replay protection and budgets across replicas, PostgreSQL, migrations, health checks, metrics, defences against a dishonest registry, crash-safe key rotation — with adversarial, concurrency and end-to-end tests. **It has not had an independent security audit yet**; see the [threat model](docs/threat-model.md) for what that means and for the known gaps.

Each agent gets a **self-certifying DID** backed by an Ed25519 keypair. It proves who it is by **signing every request**, so no API key or bearer token ever crosses the wire. Keys can be **rotated** safely, and an agent can be **killed** by itself or by the human or org that owns it. Anyone can check all of this without trusting the registry.

On top of identity, **capability grants** say what an agent may do. A person issues an agent a short-lived, scoped grant. The agent can pass a *narrower* slice to a sub-agent, and every action traces back to the human who authorized it. Revoking a grant, or switching off any agent in the chain, cuts off everything below it.

```
did:agent:QmfJZCnucexGhSZqdsAcKnFcv4RxyhPFMUiGjQmDRiMxux
          └─ sha2-256 multihash of the agent's signed inception event
```

## Documentation

| | |
|---|---|
| [Why AgentAuth](docs/why.md) | The problem, and why API keys, OAuth and mTLS fall short for agents |
| [Architecture](docs/architecture.md) | Components, request flow, how authority and limits propagate |
| [Protocol spec](docs/protocol.md) | Wire formats and verification rules, for other implementations |
| [Integration guide](docs/integration-guide.md) | Adding AgentAuth to an agent or a service |
| [Threat model](docs/threat-model.md) | What's defended against, and the known gaps |
| [Operations](docs/operations.md) | Deploying (Docker, PostgreSQL, Redis), configuration, monitoring, scaling, key management, incident response, upgrading |
| [Design decisions](docs/design-decisions.md) | Why things are the way they are |
| [TypeScript verifier](ts/README.md) | Verifying agents from Node, Deno, Bun, browsers or edge workers |
| [Security review (Oct 2026)](docs/security-audit-2026-10.md) · [Audit brief](docs/audit-brief.md) | Internal review findings and fixes (not an independent audit); scope for external auditors |
| [Glossary](docs/glossary.md) · [Roadmap](docs/roadmap.md) · [Changelog](CHANGELOG.md) · [Security](SECURITY.md) | |

## Why not just API keys?

| Problem with API keys for agents | AgentAuth |
|---|---|
| Shared secrets leak through logs, prompts and tool output | Private key never leaves the agent; requests carry signatures |
| A leaked key can be replayed anywhere, forever | Signatures are bound to method, path, body, audience (host), a timestamp and a single-use nonce |
| Identity = whatever the issuer's database says | DID is derived from the agent's own key material; the registry can't mint or reassign it |
| Rotation means coordinating a new secret everywhere | Rotate with one call; relying parties pick up the new key automatically |
| Stolen key = full takeover | **Pre-rotation**: the next key is committed in advance, so the current key alone can't rotate the identity |
| No link between an agent and who's responsible for it | Optional **controller** (a human or org DID) countersigns the agent's creation and holds a kill switch |

## Who it's for

- **Teams building AI agents** that call internal or third-party APIs and want something safer than a shared API key: a per-agent identity, no secrets on the wire, and safe key rotation.
- **Service and API owners** who accept calls from agents and need to know *which* agent is calling, *who* authorized it, and *what* it may do, with budgets, rate limits and resource limits enforced for them.
- **MCP server authors** who want to require a grant per tool (see [MCP servers](docs/integration-guide.md#8-mcp-servers)).
- **Platform and security teams** who need to answer "which agents can spend money, and on whose authority?", keep an audit trail, and switch off one agent, or everything it delegated, instantly.
- **Developers of agent frameworks and tooling** who want a verifiable identity and delegation layer instead of inventing one. The [protocol spec](docs/protocol.md) is written so it can be implemented in other languages.

**What you need:** Python 3.10 or newer. Running your own registry is optional for development (`agentauth serve`); a production deployment adds PostgreSQL and Redis (see [operations](docs/operations.md)).

**Licensing:** AgentAuth is open source under the [Apache License 2.0](LICENSE), so individuals, companies and open-source projects can use, modify and redistribute it, including commercially, under that license's terms.

**Not a fit (yet):** protecting high-value assets before an independent security audit, replacing human login (people still sign in as they do today), or acting as a general policy engine. See [Why AgentAuth](docs/why.md#what-it-isnt) and the [threat model](docs/threat-model.md).

## Concepts

**Key event log (KEL).** An identity is an append-only, hash-chained list of signed events:

| Event | Signed by | Effect |
|---|---|---|
| `inception` | the agent's first key (+ controller countersignature, if one is set) | Creates the DID and commits to `next = H(next_pubkey)` |
| `rotation` | the **pre-committed** next key | That key becomes current, and a new `next` commitment is made |
| `deactivation` | the pre-committed recovery key, **or** the controller's current key | Permanently disables the identity |

The DID equals `H(inception)`. Every event carries `prev = H(previous event)`. That means a client that downloads the log can replay it (`verify_log`) and compute the current key on its own. The registry acts as a **witness** (it validates events and serves them) but not as an **authority**.

**Split keys.** The SDK stores two files:
- `<name>.key.json` holds the current signing key. This is what the running agent needs.
- `<name>.recovery.json` holds the next key. You only need it to rotate or self-deactivate.

Keep the recovery file somewhere the agent runtime can't reach (use `--recovery-dir`). Both files can be encrypted with `AGENTAUTH_PASSPHRASE` (scrypt + AES-256-GCM) and are written with mode `0600`.

**Request signing.** Each request carries this header:

```
Authorization: AgentSig did="…",kid="…#key-1",aud="api.example.com",ts="…",nonce="…",sig="…"
```

`sig` is an Ed25519 signature over `agentauth-request/1 \n METHOD \n aud \n path?query \n ts \n nonce \n sha256(body) \n sha256(AgentGrant header)`. A verifier checks five things: the audience matches its own host, the timestamp falls within ±120s, the `kid` is the agent's current key, the signature is valid, and the nonce hasn't been seen before (by *any* replica, when the replay cache is shared through Redis).

## Capability grants & delegation

A **grant** is a signed statement: *"`iss` lets `sub` do `scope` at `aud` until `exp`, and `sub` may re-delegate `depth` more times."*

```
arunima (human)  ──grant: tools.*  @tools.example  depth=1──▶  researcher
researcher       ──grant: tools.search  (⊆ parent)  depth=0──▶  summarizer
```

The summarizer calls the tool service with its signed request plus the whole chain in an `AgentGrant` header. The service accepts the call only when all of these hold:

| Check | Why |
|---|---|
| Every link is signed by its issuer's **current** key | No forged or stale grants |
| Each link's issuer is the previous link's subject, and it references the parent by id | The chain is unbroken |
| Scopes, audiences and validity window only **shrink**; depth strictly decreases | Delegation can't escalate |
| The leaf's subject is the agent that signed the request | A stolen grant is useless to anyone else |
| The request signature covers the `AgentGrant` header | The agent explicitly asserts which authority it's using, per request |
| The root issuer is a **principal the service trusts** for those scopes (`root_policy`) | The service decides whose word counts, and for what |
| No identity in the chain is deactivated, and no grant in the chain is revoked | Revocation and kill switches **cascade** |

**Scopes** are dotted action names with a trailing wildcard. For example, `tools.*` covers `tools.search` and `tools.web.fetch`, but not `tools` itself. `*` covers everything.

**Lifetimes:** grants default to 15 minutes, with a maximum of 24 hours. A child grant's expiry is clamped to its parent's.

**Revocation:** an issuer revokes one of its grants by id (`POST /v1/revocations`). Revocations are keyed by *(issuer, grant id)*, so nobody can revoke a grant they didn't issue. Services check revocations through the registry, which returns the issuer-signed revocation as a proof the service verifies itself. A "not revoked" answer is cached for a few seconds.

**Key rotation:** grants are tied to the issuer's key at the time of issue. After an issuer rotates, its outstanding grants must be re-issued. Keeping grants short-lived makes this cheap.

## Limits: resources, spend, rate, uses

Scopes say *which actions* an agent may take. **Limits** say *on what* and *how much*. Every field is optional:

```json
"limits": {
  "resources": ["/reports/*", "repo:acme/website"],
  "spend":     {"unit": "USD-cents", "per_call": 2000, "total": 5000},
  "rate":      {"count": 10, "per": 60},
  "uses":      100
}
```

| Limit | Meaning | Enforced |
|---|---|---|
| `resources` | What the call may touch. Each pattern is exact or ends in `*` (prefix match). Requested names containing `..`, `.` or `*` are refused. | Per call |
| `spend.per_call` | Max amount for one call | Per call |
| `spend.total` | Max amount across all calls under this grant | Ledger (Redis for several replicas) |
| `rate` | Max `count` calls per `per` seconds (sliding window) | Ledger |
| `uses` | Max total calls | Ledger |

**Only tightening.** A delegated grant must stay inside its parent on every limit: a subset of resources, lower per-call and total spend, a slower rate, fewer uses. It can't drop a limit its parent has. The SDK fills in anything you leave unset from the parent, and a hand-crafted grant that loosens a limit is rejected by the service.

**Every link is enforced, and counters are shared.** The service charges each call against the ledger of *every* grant in the chain, all-or-nothing. Say you give an agent a 50 USD budget, and it hands two sub-agents 30 USD each. Together they still can't spend more than 50 USD, and the same goes for rate and use limits.

**Endpoints declare what they touch and cost:**

```python
@app.get("/files")
def read(path: str, agent = Depends(require("files.read", resource=lambda r: r.query_params["path"]))): ...

async def price(r): return (await r.json())["amount_cents"]

@app.post("/purchase")
def purchase(body: dict, agent = Depends(require("payments.buy", amount=price, unit="USD-cents"))):
    ok = charge_card(...)
    if not ok:
        agent.refund()          # give the spend back to every budget in the chain
```

**Fail-closed rules:**
- A resource-limited grant is refused at any endpoint that doesn't declare a resource.
- An unknown limit field makes the grant invalid, rather than being ignored.
- A mismatched spend unit is refused.
- Limits apply to *all* scopes in a grant. To give an agent differently limited capabilities (a spending budget *and* read access to `/reports/*`), issue two grants.

Amounts are integers in the smallest unit (such as cents); floats are never signed.

## Quick start

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m pytest                        # ~290 tests; Redis/PostgreSQL ones skip unless configured:
# AGENTAUTH_TEST_REDIS_URL=redis://localhost:6379/0 \
# AGENTAUTH_TEST_POSTGRES_URL=postgresql://postgres@localhost/agentauth_test python -m pytest

agentauth serve --db agentauth.db &     # registry on 127.0.0.1:8000

agentauth init arunima --meta kind=human                  # a human principal
agentauth init researcher --controller arunima \
                          --meta model=claude             # an agent she owns
agentauth whoami researcher             # authenticated call, signed with the agent's key
agentauth rotate researcher             # move to the pre-committed key (crash-safe)
agentauth resolve did:agent:… --verify  # replay the full log locally
agentauth agents arunima                # everything arunima controls
agentauth deactivate did:agent:… --as arunima             # kill switch

# Sign a request for use with curl:
curl -H "Authorization: $(agentauth sign researcher GET http://127.0.0.1:8000/v1/whoami)" \
     http://127.0.0.1:8000/v1/whoami
```

### Grants end to end

```bash
agentauth serve &                                            # registry :8000
agentauth init arunima
agentauth init researcher --controller arunima
agentauth init summarizer --controller researcher

# A demo tool service that trusts arunima to authorize tools.*
python examples/tool_service.py --trust $(agentauth show arunima | jq -r .did) --port 9000 &

# arunima → researcher (may delegate once) → summarizer (search only)
agentauth grant arunima researcher --scope 'tools.*' --aud 127.0.0.1:9000 --depth 1 -o researcher.grant
agentauth grant researcher summarizer --scope tools.search --aud 127.0.0.1:9000 \
          --parent researcher.grant -o summarizer.grant
agentauth inspect summarizer.grant

# Call the service as the summarizer (prints the Authorization + AgentGrant headers)
agentauth sign summarizer POST http://127.0.0.1:9000/search --data '{"q":"hi"}' --grant summarizer.grant

# Revoke the root grant; the summarizer loses access too
agentauth revoke arunima <grant-id-from-inspect>

# Limits: a 50 USD budget (max 20 USD per call, 10 calls/min) that can be split once
agentauth grant arunima shopper --scope 'payments.*' --aud 127.0.0.1:9000 --depth 1 \
          --budget 5000 --per-call 2000 --rate 10/60 -o pay.grant
agentauth grant shopper helper --scope payments.buy --aud 127.0.0.1:9000 \
          --budget 3000 --parent pay.grant -o helper.grant       # --budget 9000 would be refused
# Read-only access to /reports/* only
agentauth grant arunima shopper --scope files.read --aud 127.0.0.1:9000 --resource '/reports/*' -o files.grant
```

### Production deployment

```bash
cp .env.example .env            # set passwords and AGENTAUTH_AUDIENCES
docker compose up -d            # PostgreSQL + Redis + migration job + registry (3 workers)
curl -fsS localhost:8000/readyz
```

See [operations](docs/operations.md) for configuration, TLS proxies, metrics, backups, scaling and upgrading from v0.3.

## Using it from code

**As an agent**, calling any service:

```python
from agentauth import AgentIdentity, RegistryClient
import httpx

reg = RegistryClient("https://registry.example.com")
me, inception = AgentIdentity.create(name="researcher", meta={"model": "claude"})
reg.register(inception)
me.save("~/.agentauth", "researcher", passphrase=PASSPHRASE, recovery_dir="/secure/vault")

httpx.post("https://tools.example.com/search", json={"q": "…"}, auth=me.httpx_auth())
me.rotate_and_save(reg, "~/.agentauth", "researcher", passphrase=PASSPHRASE, recovery_dir="/secure/vault")
```

**Granting and delegating authority:**

```python
from agentauth import Limits

root  = human.grant(researcher.did, ["tools.*"], ["tools.example.com"], ttl=900, depth=1,
                    limits=Limits.build(resources=["repo:acme/*"], rate=(30, 60)))
chain = researcher.grant(summarizer.did, ["tools.search"], ["tools.example.com"], parent=root,
                         limits=Limits.build(resources=["repo:acme/website"], uses=20))

httpx.post("https://tools.example.com/search", json={"q": "…"}, auth=summarizer.httpx_auth(chain))
reg.revoke_grant(human, root.leaf.id)   # summarizer is cut off too
```

**As a service** that requires scoped authority:

```python
from agentauth import GrantVerifier, RegistryRevocationChecker, trust_principals
from agentauth.backends.redis import RedisNonceCache, RedisUsageLedger
from agentauth.integrations import fastapi_authorizer

reg  = RegistryClient("https://registry.example.com")
keys = RegistryKeyResolver(reg, ttl=30)
require = fastapi_authorizer(
    RequestVerifier(keys, audiences={"tools.example.com"},
                    nonce_cache=RedisNonceCache(REDIS_URL)),       # shared by all replicas
    GrantVerifier(keys,
                  root_policy=trust_principals({ORG_DID: ["tools.*"]}),
                  revoked=RegistryRevocationChecker(reg, ttl=5),
                  ledger=RedisUsageLedger(REDIS_URL)),              # budgets shared by all replicas
)

@app.post("/search")
def search(body: dict, agent = Depends(require("tools.search"))):
    return {"caller": agent.did, "on_behalf_of": agent.principal, "chain": agent.via}
```

**As a service** that only needs identity (no grants):

```python
from fastapi import Depends, FastAPI
from agentauth import RegistryClient, RegistryKeyResolver, RequestVerifier
from agentauth.integrations import fastapi_dependency

resolver = RegistryKeyResolver(RegistryClient("https://registry.example.com"), ttl=30)
require_agent = fastapi_dependency(RequestVerifier(resolver, audiences={"tools.example.com"}))

app = FastAPI()

@app.post("/search")
def search(body: dict, agent = Depends(require_agent)):
    return {"hello": agent.did}
```

`RegistryKeyResolver` replays the full log by default, so a compromised registry can't slip in a different key, and pins what it has verified, so a registry that later rolls a log back (say, to hide a deactivation) is caught. If an agent presents a newer `kid` than the one cached, the resolver refreshes immediately, so a rotation doesn't cause a 30-second outage.

**Any ASGI framework, and MCP servers**, via `agentauth.asgi.AgentAuthMiddleware`; `mcp_rules()` requires a grant scope per MCP tool (`mcp.tools.<name>`). See the [integration guide](docs/integration-guide.md#8-mcp-servers).

## Registry API

| Method & path | Purpose |
|---|---|
| `POST /v1/identities` | Register an inception event (optionally gated by a registration token) |
| `GET /v1/identities` | Page through all registered DIDs (for mirrors and audits) |
| `POST /v1/identities/{did}/events` | Append a rotation or deactivation |
| `GET /v1/identities/{did}` | DID resolution result (DID document + metadata) |
| `GET /v1/identities/{did}/log` | Full signed key event log |
| `GET /v1/identities/{did}/agents` | Agents controlled by `did` |
| `POST /v1/revocations` | Record an issuer-signed grant revocation |
| `POST /v1/revocations/check` | `{"grants": [[issuer, id], …]}` → the subset that is revoked, with signed proofs |
| `GET /v1/whoami` | Echoes the authenticated caller (requires `AgentSig`) |
| `GET /v1/info` | Version, protocol and schema versions |
| `GET /healthz` · `GET /readyz` · `GET /metrics` | Liveness · readiness (database, Redis, schema) · Prometheus metrics |

## Layout

```
agentauth/
  crypto.py          Ed25519, base58/multibase/multikey, canonical JSON, digests, Signer interface
  identity.py        Key event log: event construction + pure, strict verification
  httpsig.py         Request signing / verification, replay cache interface
  grants.py          Capability grants, delegation chains, scope algebra, revocation
  limits.py          Resource / spend / rate / use limits, attenuation rules, in-memory ledger
  keystore.py        Encrypted, atomically written split key files
  sdk.py             AgentIdentity, RegistryClient, RegistryKeyResolver, revocation checker, httpx auth
  witness.py         Log pins, RegistryPool, equivocation detection
  backends/redis.py  Redis replay cache and atomic usage ledger
  integrations.py    FastAPI dependencies: identity-only and scope-requiring
  asgi.py            Framework-agnostic ASGI middleware; MCP tool scopes
  audit.py           Hash-chained, signed audit log
  store.py           SQLite and PostgreSQL persistence, migrations, integrity check
  server.py          Registry (FastAPI) with limits, health, metrics, logs
  config.py          Registry settings from the environment
  ratelimit.py       Per-address rate limiting (memory or Redis)
  observability.py   JSON logging, Prometheus metrics
  cli.py             `agentauth` command
ts/                  TypeScript verifier (KELs, AgentSig, grant chains, registry client); zero runtime deps
test-vectors/        Cross-implementation test vectors, generated by scripts/generate_test_vectors.py
scripts/             Test-vector generator
deploy/              requirements.lock (hash-pinned, incl. the build backend) for the image
docs/                Why, architecture, protocol spec, guides, threat model, decisions
examples/            tool_service.py: a demo service with scoped, resource- and spend-limited endpoints
tests/               Unit, adversarial, concurrency, Redis/PostgreSQL and end-to-end tests
Dockerfile, docker-compose.yml, .env.example
```

## Threat model & limitations (v0.4)

**Covered** (designed and tested against; see the [threat model](docs/threat-model.md)):
- Forged identities and tampered logs
- Theft of the current key alone (it can't rotate)
- Request replay, whether across endpoints, across services, across replicas (with Redis) or over time
- Body, header and encoding tampering (duplicate parameters, non-canonical signatures)
- A registry that substitutes keys, rolls logs back after a service has seen them, forks logs across a registry pool, or falsely claims grants are revoked
- Squatting on a controller (the controller has to countersign)
- Privilege escalation through delegation, including unknown constraint fields
- Grant theft and grant swapping
- Grants from principals the service doesn't trust
- Revoked grants, or chains passing through deactivated agents
- Sub-agents exceeding their parent's resources, budget, rate or use count, even in aggregate and across replicas
- Path traversal in resource names
- Losing a recovery key to a crash mid-rotation
- Registry abuse: oversized bodies, crafted JSON, request floods

**Not yet covered:**
- **No independent audit.** An internal review is done ([findings](docs/security-audit-2026-10.md)), but it isn't a substitute. Don't protect high-value assets with it until there has been an external audit.
- **Theft of both keys.** An attacker holding both the current and recovery keys owns the identity; only a controller can kill it. Keep the recovery key offline or in an HSM/KMS (any `Signer` works; no KMS adapters ship yet).
- **Split views against a single client.** A registry can still show a client that only ever talks to it a consistent but different history, or hide a revocation. Use several registries (`RegistryPool`); gossip or a transparency log is on the roadmap.
- **Shared state must be configured.** The in-memory replay cache and ledger are only correct for a single process. `agentauth serve` enforces this; services you build must use the Redis backends when they run more than one process.
- **Revocation and deactivation aren't instant.** Services cache results (default 30 s for keys, 5–10 s for revocations). Set the TTLs to 0 where you need immediate effect.
- **Services must declare cost honestly.** Spend limits only bind endpoints that pass `amount=`.
- **Calls are counted when authorized, not when completed.** Failed calls still count toward rate and use limits. Spend can be refunded explicitly.

## Roadmap

Shipped: identity (v0.1), delegated grants (v0.2), limits (v0.3), production hardening (v0.4). Unreleased: an internal security review with all findings fixed, and a TypeScript verifier sharing test vectors with Python. Next: split-view detection via gossip or a transparency log, KMS/HSM signer adapters and threshold recovery, TypeScript signing and issuing, Kubernetes packaging, and an independent security review. See the full [roadmap](docs/roadmap.md).

## License

AgentAuth is licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for copyright and trademark terms. Contributions are accepted under the [Contributor License Agreement](CLA.md).

Copyright 2026 [Invaris Labs](https://www.invarislabs.com/).

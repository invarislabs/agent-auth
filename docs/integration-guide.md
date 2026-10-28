# Integration guide

There are two sides to integrating AgentAuth:

- **[Agent side](#agent-side):** you're building an agent that calls services.
- **[Service side](#service-side):** you run an API (or an MCP server) that agents call.

Both use the same package:

```bash
pip install "invaris-agentauth[server]"          # [server] adds FastAPI + uvicorn
pip install "invaris-agentauth[server,redis]"    # + shared replay cache and budgets for several replicas
```

The PyPI name is `invaris-agentauth`; the import name is `agentauth`. The unrelated PyPI project `agentauth` provides the same import name, so don't install both.

---

## Agent side

### 1. Create and register an identity

```python
from agentauth import AgentIdentity, RegistryClient

reg = RegistryClient("https://registry.example.com")

me, inception = AgentIdentity.create(name="researcher", meta={"model": "claude", "team": "growth"})
reg.register(inception)

me.save("~/.agentauth", "researcher", passphrase=PASSPHRASE, recovery_dir="/secure/vault")
print(me.did)          # did:agent:Qm…
```

- `save` writes two files: `researcher.key.json` (the current key, which the running agent needs) and `researcher.recovery.json` (the pre-committed next key). **Put the recovery file somewhere the agent runtime can't read.** See [operations → key management](operations.md#key-management).
- Pass `passphrase=`, or set `AGENTAUTH_PASSPHRASE` / `AGENTAUTH_PASSPHRASE_FILE`, to encrypt both files.
- If the registry requires a registration token, pass `RegistryClient(url, registration_token=...)` or set `AGENTAUTH_REGISTRATION_TOKEN`.

**With an owner.** If a human or org identity should own the agent, and be able to switch it off, pass it as the controller. The controller's key countersigns the inception:

```python
owner = AgentIdentity.load("~/.agentauth", "arunima")
me, inception = AgentIdentity.create(name="researcher", controller=owner)
```

**Recovery key in an HSM or KMS.** Anything with a `public_multikey` property and a `sign(message) -> base64url signature` method is a `Signer` and can stand in for a `KeyPair`, e.g. as the next key of a rotation (`identity.prepare_rotation(new_next=hsm_signer)`) or in `make_inception`. External signers aren't written to key files.

### 2. Load it at runtime

```python
me = AgentIdentity.load("~/.agentauth", "researcher")   # no recovery_dir: enough to sign, not to rotate
```

### 3. Call a service

```python
import httpx

httpx.post("https://api.example.com/search", json={"q": "…"}, auth=me.httpx_auth())
```

`httpx_auth()` works with both `httpx` and `httpx2` clients. It signs the method, URL, body, timestamp and a fresh nonce on every request.

Any other HTTP client works too. Compute the headers yourself and send them **with exactly the bytes you signed**:

```python
body = json.dumps({"q": "…"}).encode()
headers = me.headers("POST", url, body)               # {"Authorization": "AgentSig …"}
headers = me.headers("POST", url, body, grants=chain)  # adds "AgentGrant"
```

Each signed request is single-use: retrying must sign again (a fresh nonce), not resend the same headers.

### 4. Act on someone's behalf (grants)

Services that need to know *who authorized* an agent require a **grant chain**. Someone the service trusts (a principal) issues one:

```python
chain = owner.grant(
    me.did,
    scopes=["tools.search", "files.read"],
    audiences=["api.example.com"],
    ttl=900,                     # seconds; max 86400
)
```

The agent sends the chain with each request:

```python
httpx.post("https://api.example.com/search", json={"q": "…"}, auth=me.httpx_auth(chain))
```

Grants are just strings (`chain.encode()`). Pass them to the agent however you pass it configuration, and treat them as sensitive. They're useless without the subject's private key, but there's no reason to leak them.

### 5. Delegate to a sub-agent

If a grant allows it (`depth ≥ 1`), the agent can hand a **narrower** slice to another agent:

```python
root = owner.grant(me.did, ["tools.*"], ["api.example.com"], depth=1)
child = me.grant(helper.did, ["tools.search"], ["api.example.com"], parent=root)
# the helper then calls with helper.httpx_auth(child)
```

The SDK refuses anything that would widen authority: scopes, audiences, lifetime, depth or limits. Any service verifying the chain would reject it anyway.

### 6. Add limits

```python
from agentauth import Limits

pay = owner.grant(me.did, ["payments.buy"], ["api.example.com"], depth=1,
                  limits=Limits.build(per_call=2000, total=5000, rate=(10, 60)))   # cents; 10 calls/min
files = owner.grant(me.did, ["files.read"], ["api.example.com"],
                    limits=Limits.build(resources=["/reports/*"]))
```

Limits apply to **every scope in the grant**. If the agent needs a budget for one capability and a resource restriction for another, issue two grants, as above, and send whichever one the call needs.

### 7. Rotate, revoke, deactivate

```python
admin = AgentIdentity.load("~/.agentauth", "researcher", recovery_dir="/secure/vault")
admin.rotate_and_save(reg, "~/.agentauth", "researcher", recovery_dir="/secure/vault")

reg.revoke_grant(owner, root.leaf.id)             # kills root and everything delegated from it
reg.deactivate_controlled(owner, me.did)          # owner's kill switch
reg.deactivate_self(admin)                        # agent retires itself (needs the recovery key)
```

`rotate_and_save` saves the new next key to `<name>.pending.json` before submitting, confirms the rotation against the registry's log, and only then rewrites the key files. If it's interrupted, call it again to finish. (`reg.rotate(identity)` still exists, but holds the new key only in memory until you save.)

After a rotation, grants the rotated identity *issued* must be re-issued. Grants it *received* are unaffected.

### 8. Several registries

```python
from agentauth import RegistryPool
reg = RegistryPool([RegistryClient("https://reg-a.example.com"), RegistryClient("https://reg-b.example.org")])
reg.register(inception)            # written to both
admin.rotate_and_save(reg, ...)    # also written to both, and lagging copies are backfilled
```

A registry that's unreachable or rejects a write doesn't stop the others; the write fails only if every registry fails. Reads need all registries to answer unless you lower `read_quorum`, so with a pool always rotate with `rotate_and_save` (it can resume if confirming the rotation fails).

---

## Service side

### 1. Identity only: "which agent is this?"

```python
from fastapi import Depends, FastAPI
from agentauth import RegistryClient, RegistryKeyResolver, RequestVerifier
from agentauth.integrations import fastapi_dependency

reg = RegistryClient("https://registry.example.com")
keys = RegistryKeyResolver(reg, ttl=30)
require_agent = fastapi_dependency(RequestVerifier(keys, audiences={"api.example.com"}))

app = FastAPI()

@app.get("/me")
def me(agent = Depends(require_agent)):
    return {"did": agent.did}
```

- **`audiences`** must contain the `host[:port]` that clients put in the URL. List every public hostname the service answers to.
- If one app serves several audiences and routes by host, pass `bind_host=True` so a request signed for one host can't be sent to another. (Leave it off if your proxy rewrites `Host`.)
- With a custom replay cache, give it a TTL of at least `2 × max_skew + 1` seconds; the verifier refuses anything shorter.
- Use this when all you need is a stable, unforgeable caller ID, for example for allow-lists or per-agent quotas you manage yourself.

### 2. Scoped authority: "who allowed this, and to do what?"

```python
from agentauth import GrantVerifier, RegistryRevocationChecker, trust_principals
from agentauth.integrations import fastapi_authorizer

require = fastapi_authorizer(
    RequestVerifier(keys, audiences={"api.example.com"}),
    GrantVerifier(
        keys,
        root_policy=trust_principals({
            ORG_DID:      ["tools.*", "files.*", "payments.*"],
            CONTRACTOR:   ["tools.search"],
        }),
        revoked=RegistryRevocationChecker(reg, ttl=5),
    ),
)

@app.post("/search")
def search(body: dict, agent = Depends(require("tools.search"))):
    return {"caller": agent.did, "on_behalf_of": agent.principal, "chain": agent.via}
```

The **root policy** is where your service decides whose authority counts. `trust_principals` takes a static dict. For anything dynamic, such as principals stored in your user database, pass any callable `(principal_did, audience) → scopes or None`:

```python
def root_policy(did, audience):
    user = db.users.find_one(agentauth_did=did)
    return user.allowed_scopes if user and user.active else None
```

If the callable raises, the request is refused with 503.

**Choosing scope names.** Use `resource.action`, with hierarchy where it helps: `files.read`, `files.write`, `payments.buy`, `tools.web.fetch`. Principals can then grant `files.*` or just `files.read`.

**Revocation proofs.** `RegistryRevocationChecker` verifies the issuer-signed proof the registry returns with every "revoked" answer. By default a claim without a valid proof still counts as revoked (fail closed) and is logged; `on_unproven="ignore"` honours only proven revocations, for deployments where a registry falsely revoking grants is the bigger risk.

### 3. Resource and spend limits

Endpoints declare what a call touches and what it costs. The authorizer enforces every link's limits before your handler runs:

```python
@app.get("/files")
def read_file(path: str,
              agent = Depends(require("files.read", resource=lambda r: r.query_params["path"]))):
    ...

async def price(request):
    return int((await request.json())["amount_cents"])

@app.post("/purchase")
def purchase(body: dict, agent = Depends(require("payments.buy", amount=price, unit="USD-cents"))):
    if not charge_card(body):
        agent.refund()                       # returns the spend to every budget in the chain
        raise HTTPException(502, "payment failed")
    return {"ok": True, "charged": agent.charged}
```

Rules of thumb:

- **Declare a `resource` on every endpoint that touches named things.** A grant with resource limits is refused at endpoints that don't declare one. That's intentional (fail closed).
- **Declare an `amount` on every endpoint that spends.** Spend limits can only bind endpoints that report a cost. Amounts are integers; a float or a string is refused.
- **Use a consistent unit string** (`"USD-cents"`, `"tokens"`, `"credits"`). A grant in one unit is refused at an endpoint that charges in another.
- **Normalize resource names** the same way principals write patterns. For example, strip trailing slashes and use absolute paths. `..` and `.` segments are rejected for you.
- `refund()` can return at most what this request was charged.

### 4. More than one process or replica

The default replay cache and usage ledger live in process memory. As soon as two processes verify requests for the same audience (two uvicorn workers count), share them through Redis, or a request can be replayed once per process and every limit multiplies:

```python
from agentauth.backends.redis import RedisNonceCache, RedisUsageLedger

verifier = RequestVerifier(keys, audiences={"api.example.com"}, nonce_cache=RedisNonceCache(REDIS_URL))
grants = GrantVerifier(keys, root_policy=..., revoked=..., ledger=RedisUsageLedger(REDIS_URL))
```

If Redis is down, requests are refused with 503. See [operations → scaling](operations.md#scaling).

### 5. Defending against a dishonest registry

`RegistryKeyResolver` remembers the newest log it has verified for each DID. If a registry later serves a shorter log (hiding events) or a conflicting one, it raises `EquivocationError` and requests for that DID fail with 503. To make that memory survive restarts, and to cross-check several registries:

```python
from agentauth import RegistryPool, SQLitePins

pool = RegistryPool([RegistryClient(A), RegistryClient(B)])
keys = RegistryKeyResolver(pool, ttl=30, pins=SQLitePins("/var/lib/my-service/pins.db"))
revoked = RegistryRevocationChecker(pool, ttl=5)
```

### 6. Audit log

```python
from agentauth import AuditLog, KeyPair

audit = AuditLog("/var/lib/my-service/audit.db", signer=SERVICE_KEY, instance="api-1")
require = fastapi_authorizer(verifier, grants, audit=audit)
```

If an *allowed* decision can't be written to the log, the call is refunded and refused with 503. Every decision made after the caller's signature verified is appended to a hash-chained, optionally signed log: agent, principal, full delegation path, grant ids, scopes, resource, amount, outcome and status. Export `audit.head()` regularly to another system, and check the log with `agentauth audit /var/lib/my-service/audit.db --key <multikey> --head SEQ:DIGEST`.

### 7. Not using FastAPI? Any ASGI app

`agentauth.asgi.AgentAuthMiddleware` works with any ASGI framework (Starlette, Litestar, Quart, …) and doesn't import FastAPI:

```python
from agentauth.asgi import PUBLIC, AgentAuthMiddleware, Requirement

def rules(req):
    if req.path == "/healthz":
        return PUBLIC                                   # no authentication
    if req.path == "/search":
        return Requirement(scopes=["tools.search"])     # grant required
    return Requirement(scopes=["admin"])                # deny by default: anything unlisted needs a strong grant

app = AgentAuthMiddleware(app, verifier=verifier, grants=grants, rules=rules, audit=audit)
```

The result is available to your handlers as `request.state.agentauth` (a `VerifiedAgent` or `AuthorizedAgent`). `scope["user"]` is set to an `AgentUser` whose `identity` is the agent's DID, so `request.user.is_authenticated` is true and anything keyed on the user sees the agent.

Some behaviour to know when writing rules:

- **`req.path` is the route path.** It is relative to the app the middleware wraps: under `Mount("/api", app=...)`, a request to `/api/search` has `req.path == "/search"`, matching what the app routes on. `req.full_path` keeps the prefix.
- **Write rules deny-by-default.** Return the strictest requirement unless a path is known to need less, so a route added later isn't left open.
- **WebSockets are checked too.** The handshake goes through `rules` with `req.websocket` true, method `GET` and an empty body. Unless the rule is `PUBLIC`, the client must sign the handshake: `agent.authorization("GET", "https://host/ws", b"", grants)` as the `Authorization` header. Otherwise the connection is closed with code 1008 before your app sees it. A long-lived connection isn't re-checked after it opens.
- **Duplicate security headers are refused.** A request with two `Authorization`, `Host` or `AgentGrant` headers gets 400.

### 8. MCP servers

For an MCP server using the streamable HTTP transport, `mcp_rules()` maps JSON-RPC calls to scopes: every request needs `mcp.session`, and a `tools/call` for tool `X` additionally needs `mcp.tools.X`. A principal grants `mcp.*` for everything, or `["mcp.session", "mcp.tools.search"]` for one tool.

```python
from mcp.server.mcpserver import MCPServer
from agentauth.asgi import AgentAuthMiddleware, mcp_rules

server = MCPServer("tools")
app = AgentAuthMiddleware(server.streamable_http_app(), verifier=verifier, grants=grants,
                          rules=mcp_rules(resource=lambda tool, args: args.get("path")))
```

`resource=` lets resource limits on grants apply to tool arguments.

The middleware binds each `Mcp-Session-Id` to the agent that opened it. Another agent presenting the same session id gets 403. The binding is held in the worker's memory, so with several workers or replicas, route a session's requests to the same worker (sticky sessions), or enforce ownership in the MCP server's own session store. `mcp_rules` authorizes `tools/call` per tool. Other methods (`resources/read`, `prompts/get`, …) need only `mcp.session`, so add your own checks if they expose sensitive data.

On the client side, give the MCP client an HTTP client that signs every request:

```python
import httpx2
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

http = httpx2.AsyncClient(auth=agent.httpx_auth(chain))
async with streamable_http_client("https://tools.example.com/mcp", http_client=http) as (read, write, *_):
    async with ClientSession(read, write) as session:
        await session.initialize()
        await session.call_tool("search", {"q": "…"})
```

Both sides are tested against the official MCP Python SDK (`mcp` 2.x, streamable HTTP, stateless JSON responses) in `tests/test_integrations.py`. SSE streaming responses and session resumption weren't specifically tested.

### 9. Framework-agnostic verification

The verifiers can be called directly:

```python
from agentauth.asgi import request_target

agent = request_verifier.verify(authorization=hdr, method=m, path=raw_path_with_query, body=raw_body, grants=grant_hdr)
authz = grant_verifier.verify(grant_hdr, requester=agent.did, audience=agent.audience)
if not authz.allows("files.read"): deny()
grant_verifier.enforce(authz, resource="/reports/q3.pdf", amount=0)
```

- Pass the **raw** request target (percent-encoding intact, plus `?query`), not a decoded path. For ASGI apps, `request_target(scope)` computes it.
- **Don't let your HTTP client follow redirects with agent credentials.** httpx doesn't by default. If you turn on `follow_redirects`, the `AgentGrant` header goes to the redirect target too. That grant can't be used without the agent's key, but it reveals the delegation chain.
- **TypeScript services.** [`ts/`](../ts/README.md) has a verifier with the same API shape (`RequestVerifier`, `GrantVerifier`, `RegistryClient`), checked against the same test vectors.
- Catch `AuthError` and `GrantError` and use their `.status`: 401/403/402/429 for the caller's problems, 400 for malformed input, 503 when a dependency (registry, Redis, policy) failed.

### 10. Tuning freshness

| Setting | Lower it for… | Cost |
|---|---|---|
| `RegistryKeyResolver(ttl=…)` | faster effect of deactivation | more registry calls |
| `RegistryRevocationChecker(ttl=…)` | faster effect of revocation | more registry calls |
| `RegistryKeyResolver(verify_logs=False)` | lower latency | trusts the registry's DID document instead of replaying the log, and disables rollback detection |

For payments or other irreversible actions, consider `ttl=0` on both.

### 11. Testing

Use FastAPI's `TestClient` with an in-process registry. `tests/test_grants.py` in this repo is a complete example:

```python
from fastapi.testclient import TestClient
from agentauth.config import Settings
from agentauth.server import create_app

settings = Settings(audiences={"testserver"}, rate_limit_writes=None, rate_limit_reads=None)
reg = RegistryClient("http://testserver", client=TestClient(create_app(db_path=":memory:", settings=settings)))
```

`python examples/tool_service.py --trust <principal DID>` runs a demo service with scoped, resource-limited and spend-limited endpoints you can call from the CLI. Add `--redis`, `--pins` and `--audit` to try the production options.

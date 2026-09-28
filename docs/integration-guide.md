# Integration guide

There are two sides to integrating AgentAuth:

- **[Agent side](#agent-side):** you're building an agent that calls services.
- **[Service side](#service-side):** you run an API that agents call.

Both use the same package:

```bash
pip install "agentauth[server]"        # [server] adds FastAPI + uvicorn
```

---

## Agent side

### 1. Create and register an identity

```python
from agentauth import AgentIdentity, RegistryClient

reg = RegistryClient("https://registry.example.com")

me, inception = AgentIdentity.create(name="researcher", meta={"model": "claude", "team": "growth"})
reg.register(inception)

me.save("~/.agentauth", "researcher", recovery_dir="/secure/vault")
print(me.did)          # did:agent:Qm…
```

- `save` writes two files: `researcher.key.json` (the current key, which the running agent needs) and `researcher.recovery.json` (the pre-committed next key). **Put the recovery file somewhere the agent runtime can't read.** See [operations → key management](operations.md#key-management).
- Set `AGENTAUTH_PASSPHRASE` (or pass `passphrase=`) to encrypt both files.

**With an owner.** If a human or org identity should own the agent, and be able to switch it off, pass it as the controller. The controller's key countersigns the inception:

```python
owner = AgentIdentity.load("~/.agentauth", "arunima")
me, inception = AgentIdentity.create(name="researcher", controller=owner)
```

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

Any other HTTP client works too. Compute the header yourself and send it:

```python
headers = {"Authorization": me.authorization("POST", url, body_bytes)}
```

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
reg.rotate(admin); admin.save("~/.agentauth", "researcher", recovery_dir="/secure/vault")

reg.revoke_grant(owner, root.leaf.id)             # kills root and everything delegated from it
reg.deactivate_controlled(owner, me.did)          # owner's kill switch
reg.deactivate_self(admin)                        # agent retires itself (needs the recovery key)
```

After a rotation, grants the rotated identity *issued* must be re-issued. Grants it *received* are unaffected.

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

**Choosing scope names.** Use `resource.action`, with hierarchy where it helps: `files.read`, `files.write`, `payments.buy`, `tools.web.fetch`. Principals can then grant `files.*` or just `files.read`.

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
- **Declare an `amount` on every endpoint that spends.** Spend limits can only bind endpoints that report a cost.
- **Use a consistent unit string** (`"USD-cents"`, `"tokens"`, `"credits"`). A grant in one unit is refused at an endpoint that charges in another.
- **Normalize resource names** the same way principals write patterns. For example, strip trailing slashes and use absolute paths. `..` and `.` segments are rejected for you.

### 4. Not using FastAPI?

The verifiers are framework-agnostic:

```python
agent = request_verifier.verify(authorization=hdr, method=m, path=path_with_query, body=raw_body, grants=grant_hdr)
authz = grant_verifier.verify(grant_hdr, requester=agent.did, audience=agent.audience)
if not authz.allows("files.read"): deny()
grant_verifier.enforce(authz, resource="/reports/q3.pdf", amount=0)
```

Catch `AuthError` (map it to 401) and `GrantError` (use its `.status`).

### 5. Tuning freshness

| Setting | Lower it for… | Cost |
|---|---|---|
| `RegistryKeyResolver(ttl=…)` | faster effect of deactivation | more registry calls |
| `RegistryRevocationChecker(ttl=…)` | faster effect of revocation | more registry calls |
| `RegistryKeyResolver(verify_logs=False)` | lower latency | trusts the registry's DID document instead of replaying the log |

For payments or other irreversible actions, consider `ttl=0` on both.

### 6. Testing

Use FastAPI's `TestClient` with an in-process registry. `tests/test_grants.py` in this repo is a complete example:

```python
from fastapi.testclient import TestClient
from agentauth.server import create_app

reg = RegistryClient("http://testserver", client=TestClient(create_app(db_path=":memory:", audiences={"testserver"})))
```

`python examples/tool_service.py --trust <principal DID>` runs a demo service with scoped, resource-limited and spend-limited endpoints you can call from the CLI.

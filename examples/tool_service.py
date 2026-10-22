"""A demo tool service that only accepts agents holding a grant from a trusted principal.

    python examples/tool_service.py --trust did:agent:… --port 9000

The principal DID you pass (e.g. your own human identity) is trusted to grant
"tools.*", "files.*" and "payments.*" here. Agents call it with a signed
request plus an AgentGrant chain.

Production-relevant options:

    --redis redis://localhost:6379/0   share replay protection and budgets between replicas
    --pins /var/lib/svc/pins.db        remember verified logs across restarts (rollback/fork detection)
    --audit /var/lib/svc/audit.db      tamper-evident log of every authorization decision
    --registry https://a,https://b     cross-check several registries
"""

import argparse

import uvicorn
from fastapi import Depends, FastAPI, HTTPException

from agentauth import (
    AuditLog,
    AuthorizedAgent,
    GrantVerifier,
    NonceCache,
    RegistryClient,
    RegistryKeyResolver,
    RegistryPool,
    RegistryRevocationChecker,
    RequestVerifier,
    SQLitePins,
    UsageLedger,
    trust_principals,
)
from agentauth.integrations import fastapi_authorizer


def build(registry_url: str, trusted: list, audiences: set, *, redis_url=None, pins_path=None, audit_path=None) -> FastAPI:
    urls = [u for u in registry_url.split(",") if u]
    reg = RegistryClient(urls[0]) if len(urls) == 1 else RegistryPool([RegistryClient(u) for u in urls])
    keys = RegistryKeyResolver(reg, ttl=30, pins=SQLitePins(pins_path) if pins_path else None)
    if redis_url:
        from agentauth.backends.redis import RedisNonceCache, RedisUsageLedger

        nonces, ledger = RedisNonceCache(redis_url), RedisUsageLedger(redis_url)
    else:
        nonces, ledger = NonceCache(ttl=241), UsageLedger()
    require = fastapi_authorizer(
        RequestVerifier(keys, audiences=audiences, nonce_cache=nonces),
        GrantVerifier(
            keys,
            root_policy=trust_principals({did: ["tools.*", "files.*", "payments.*"] for did in trusted}),
            revoked=RegistryRevocationChecker(reg, ttl=5),
            ledger=ledger,
        ),
        audit=AuditLog(audit_path) if audit_path else None,
    )
    app = FastAPI(title="Demo tool service")

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.post("/search")
    def search(body: dict, agent: AuthorizedAgent = Depends(require("tools.search"))):
        return {
            "results": [f"result for {body.get('q')!r}"],
            "caller": agent.did,
            "on_behalf_of": agent.principal,
            "chain": agent.via,
        }

    @app.post("/send-email")
    def send_email(body: dict, agent: AuthorizedAgent = Depends(require("tools.email.send"))):
        return {"sent": True, "to": body.get("to"), "caller": agent.did}

    @app.get("/files")
    def read_file(
        path: str,
        agent: AuthorizedAgent = Depends(require("files.read", resource=lambda r: r.query_params["path"])),
    ):
        return {"path": path, "content": f"(contents of {path})", "caller": agent.did}

    async def price(request):
        amount = (await request.json())["amount_cents"]
        if not isinstance(amount, int) or isinstance(amount, bool):
            raise ValueError("amount_cents must be an integer")
        return amount

    @app.post("/purchase")
    def purchase(body: dict, agent: AuthorizedAgent = Depends(require("payments.buy", amount=price, unit="USD-cents"))):
        if body.get("simulate_failure"):
            agent.refund()  # the downstream payment failed: give the budget back
            raise HTTPException(502, "payment provider failed; budget refunded")
        spent = agent.ledger.usage((agent.chain.root.iss, agent.chain.root.id))["spent"] if agent.ledger else None
        return {"bought": body.get("item"), "charged_cents": agent.charged, "root_budget_spent": spent}

    return app


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--registry", default="http://127.0.0.1:8000", help="registry URL(s), comma-separated")
    ap.add_argument("--trust", action="append", required=True, help="principal DID trusted to grant tools.* etc.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--redis", default=None)
    ap.add_argument("--pins", default=None)
    ap.add_argument("--audit", default=None)
    a = ap.parse_args()
    auds = {f"{a.host}:{a.port}", f"localhost:{a.port}", f"127.0.0.1:{a.port}"}
    uvicorn.run(build(a.registry, a.trust, auds, redis_url=a.redis, pins_path=a.pins, audit_path=a.audit),
                host=a.host, port=a.port)

"""A demo tool service that only accepts agents holding a grant from a trusted principal.

    python examples/tool_service.py --trust did:agent:… --port 9000

The principal DID you pass (e.g. your own human identity) is trusted to grant
"tools.*", "files.*" and "payments.*" here. Agents call it with a signed request plus an AgentGrant chain.
"""

import argparse

import uvicorn
from fastapi import Depends, FastAPI

from agentauth import (
    AuthorizedAgent,
    GrantVerifier,
    RegistryClient,
    RegistryKeyResolver,
    RegistryRevocationChecker,
    RequestVerifier,
    trust_principals,
)
from agentauth.integrations import fastapi_authorizer


def build(registry_url: str, trusted: list, audiences: set) -> FastAPI:
    reg = RegistryClient(registry_url)
    keys = RegistryKeyResolver(reg, ttl=30)
    require = fastapi_authorizer(
        RequestVerifier(keys, audiences=audiences),
        GrantVerifier(
            keys,
            root_policy=trust_principals({did: ["tools.*", "files.*", "payments.*"] for did in trusted}),
            revoked=RegistryRevocationChecker(reg, ttl=5),
        ),
    )
    app = FastAPI(title="Demo tool service")

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
        return int((await request.json())["amount_cents"])

    @app.post("/purchase")
    def purchase(body: dict, agent: AuthorizedAgent = Depends(require("payments.buy", amount=price, unit="USD-cents"))):
        spent = agent.ledger.usage((agent.chain.root.iss, agent.chain.root.id))["spent"]
        return {"bought": body.get("item"), "charged_cents": agent.charged, "root_budget_spent": spent}

    return app


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--registry", default="http://127.0.0.1:8000")
    ap.add_argument("--trust", action="append", required=True, help="principal DID trusted to grant tools.*")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    a = ap.parse_args()
    auds = {f"{a.host}:{a.port}", f"localhost:{a.port}", f"127.0.0.1:{a.port}"}
    uvicorn.run(build(a.registry, a.trust, auds), host=a.host, port=a.port)

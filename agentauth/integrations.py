"""Framework integrations for services that accept calls from agents."""

import inspect
from typing import Any, Callable, Optional

from fastapi import HTTPException, Request

from .grants import HEADER as GRANT_HEADER
from .grants import AuthorizedAgent, GrantError, GrantVerifier
from .httpsig import AuthError, RequestVerifier, VerifiedAgent


async def _authenticate(verifier: RequestVerifier, request: Request) -> VerifiedAgent:
    body = await request.body()
    path = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    try:
        return verifier.verify(
            authorization=request.headers.get("authorization", ""),
            method=request.method,
            path=path,
            body=body,
            grants=request.headers.get(GRANT_HEADER, ""),
        )
    except AuthError as e:
        raise HTTPException(e.status, str(e), headers={"WWW-Authenticate": "AgentSig"}) from None


def fastapi_dependency(verifier: RequestVerifier):
    """Build a FastAPI dependency that authenticates the calling agent (identity only).

        verifier = RequestVerifier(RegistryKeyResolver(RegistryClient(url)), audiences={"api.example.com"})
        require_agent = fastapi_dependency(verifier)

        @app.post("/tasks")
        def create_task(agent = Depends(require_agent)): ...
    """

    async def require_agent(request: Request) -> VerifiedAgent:
        return await _authenticate(verifier, request)

    return require_agent


def fastapi_authorizer(verifier: RequestVerifier, grants: GrantVerifier):
    """Build a factory of FastAPI dependencies that require a scope.

        require = fastapi_authorizer(request_verifier, grant_verifier)

        @app.post("/search")
        def search(agent: AuthorizedAgent = Depends(require("tools.search"))): ...

        # Endpoints that touch a named resource or cost money say so, so that
        # resource and spend limits on the grant can be enforced:
        @app.get("/files")
        def read(path: str, agent = Depends(require("files.read", resource=lambda r: r.query_params["path"]))): ...

        async def price(r): return (await r.json())["amount_cents"]
        @app.post("/buy")
        def buy(agent = Depends(require("payments.buy", amount=price, unit="USD-cents"))): ...

    The caller must (1) sign the request with its current key, (2) present an
    AgentGrant chain rooted in a principal this service trusts, whose leaf was
    issued to the caller and covers the scope, and (3) stay within every
    link's resource / spend / rate / use limits.

    Resource limits fail closed: if a grant restricts resources and the
    endpoint doesn't declare `resource`, the call is refused.
    """

    async def _eval(fn: Optional[Callable], request: Request) -> Any:
        if fn is None:
            return None
        try:
            v = fn(request)
            if inspect.isawaitable(v):
                v = await v
        except (KeyError, ValueError, TypeError) as e:
            raise HTTPException(400, f"could not determine resource/amount: {e}") from None
        return v

    def require(
        *scopes: str,
        resource: Optional[Callable] = None,
        amount: Optional[Callable] = None,
        unit: Optional[str] = None,
    ):
        async def dependency(request: Request) -> AuthorizedAgent:
            agent = await _authenticate(verifier, request)
            header = request.headers.get(GRANT_HEADER, "")
            try:
                authz = grants.verify(header, requester=agent.did, audience=agent.audience)
            except GrantError as e:
                raise HTTPException(e.status, str(e)) from None
            missing = [s for s in scopes if not authz.allows(s)]
            if missing:
                raise HTTPException(403, f"grant does not cover: {', '.join(missing)}")
            res = await _eval(resource, request)
            amt = await _eval(amount, request) or 0
            try:
                grants.enforce(authz, resource=None if res is None else str(res), amount=amt, unit=unit)
            except GrantError as e:
                raise HTTPException(e.status, str(e)) from None
            return authz

        return dependency

    return require

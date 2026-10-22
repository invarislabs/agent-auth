"""FastAPI integrations for services that accept calls from agents.

For other ASGI frameworks (or MCP servers) see `agentauth.asgi`.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable
from typing import Any, Optional

from fastapi import HTTPException, Request

from .asgi import AgentAuthMiddleware, Requirement, mcp_rules, request_target  # noqa: F401  (re-exported)
from .grants import HEADER as GRANT_HEADER
from .grants import AuthorizedAgent, GrantError, GrantVerifier
from .httpsig import AuthError, RequestVerifier, VerifiedAgent

log = logging.getLogger("agentauth.integrations")


async def _authenticate(verifier: RequestVerifier, request: Request) -> VerifiedAgent:
    body = await request.body()
    try:
        return verifier.verify(
            authorization=request.headers.get("authorization", ""),
            method=request.method,
            path=request_target(request.scope),
            body=body,
            grants=request.headers.get(GRANT_HEADER, ""),
            host=request.headers.get("host"),
        )
    except AuthError as e:
        headers = {"WWW-Authenticate": "AgentSig"} if e.status == 401 else None
        raise HTTPException(e.status, str(e), headers=headers) from None


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


def fastapi_authorizer(verifier: RequestVerifier, grants: GrantVerifier, *, audit: Any = None):
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

    `audit` (an `agentauth.audit.AuditLog`) records every decision made after
    the caller's signature verified.
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

    def _record(request, did, scopes, authz, outcome, status, reason, res=None, amt=0, unit=None):
        """Write an audit entry. If the log can't be written, an allowed call is undone
        (its charge refunded) and refused with 503: no unaudited actions."""
        if audit is None:
            return
        try:
            audit.record(agent=did, outcome=outcome, status=status, scopes=list(scopes), authz=authz,
                         resource=res, amount=amt if isinstance(amt, int) and not isinstance(amt, bool) else 0,
                         unit=unit, reason=reason, method=request.method, path=request_target(request.scope),
                         request_id=request.headers.get("x-request-id"))
        except Exception:
            log.exception("audit log write failed")
            if outcome == "allowed":
                if authz is not None and authz.charged:
                    authz.refund()
                raise HTTPException(503, "audit log unavailable") from None

    def require(
        *scopes: str,
        resource: Optional[Callable] = None,
        amount: Optional[Callable] = None,
        unit: Optional[str] = None,
    ):
        async def dependency(request: Request) -> AuthorizedAgent:
            agent = await _authenticate(verifier, request)
            header = request.headers.get(GRANT_HEADER, "")
            authz = None
            res, amt = None, 0
            try:
                authz = grants.verify(header, requester=agent.did, audience=agent.audience)
                missing = [s for s in scopes if not authz.allows(s)]
                if missing:
                    raise GrantError(f"grant does not cover: {', '.join(missing)}", 403)
                res = await _eval(resource, request)
                amt = await _eval(amount, request) or 0
                grants.enforce(authz, resource=None if res is None else str(res), amount=amt, unit=unit)
            except GrantError as e:
                _record(request, agent.did, scopes, authz, "denied", e.status, str(e), res, amt, unit)
                raise HTTPException(e.status, str(e)) from None
            except HTTPException as e:
                _record(request, agent.did, scopes, authz, "denied", e.status_code, str(e.detail), res, amt, unit)
                raise
            _record(request, agent.did, scopes, authz, "allowed", 200, None, res, amt, unit)
            return authz

        return dependency

    return require

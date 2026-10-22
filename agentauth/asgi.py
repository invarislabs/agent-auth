"""Framework-agnostic ASGI middleware that authenticates and authorizes agent requests.

Works with any ASGI app (Starlette, FastAPI, Litestar, Quart, an MCP
streamable-HTTP server, ...) without importing FastAPI.

    app = AgentAuthMiddleware(
        app,
        verifier=RequestVerifier(keys, audiences={"api.example.com"}),
        grants=GrantVerifier(keys, root_policy=trust_principals({ORG: ["tools.*"]})),
        rules=lambda req: Requirement(scopes=["tools.search"]) if req.path == "/search" else None,
    )

`rules(request)` returns what a request needs:

* ``PUBLIC`` – no authentication at all (health checks, docs).
* ``None`` – a valid AgentSig signature only (identity, no grant).
* a `Requirement` – a grant chain covering `scopes`, within every link's
  limits for `resource` and `amount`/`unit`.

The verified result is placed in ``scope["state"]["agentauth"]`` (Starlette:
``request.state.agentauth``) as a `VerifiedAgent` or `AuthorizedAgent`.

The request body is buffered (it's covered by the signature) up to
`max_body_bytes`, then replayed to the app unchanged.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Optional

from .grants import HEADER as GRANT_HEADER
from .grants import GrantError, GrantVerifier
from .httpsig import AuthError, RequestVerifier

log = logging.getLogger("agentauth.asgi")


@dataclass
class Requirement:
    scopes: list = field(default_factory=list)
    resource: Optional[str] = None
    amount: int = 0
    unit: Optional[str] = None


PUBLIC = object()  # sentinel: no authentication required


@dataclass
class AgentRequest:
    """What `rules` gets to look at."""

    method: str
    path: str  # decoded path, for routing decisions
    target: str  # raw path + query, exactly as signed
    headers: dict
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body or b"null")


def request_target(scope: Any) -> str:
    """The raw request target (path + query) as the client sent and signed it.

    Uses the ASGI ``raw_path`` (percent-encoding intact) rather than the
    decoded ``path``; falls back to ``path`` for servers that don't provide it.
    """
    raw = scope.get("raw_path")
    path = raw.decode("latin-1") if raw else scope.get("root_path", "") + scope.get("path", "")
    if "?" in path:  # some servers include the query in raw_path
        return path
    qs = scope.get("query_string", b"")
    return path + ("?" + qs.decode("latin-1") if qs else "")


async def _respond(send, status: int, detail: str, headers: Optional[list] = None) -> None:
    body = json.dumps({"detail": detail}).encode()
    hdrs = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())] + (headers or [])
    await send({"type": "http.response.start", "status": status, "headers": hdrs})
    await send({"type": "http.response.body", "body": body})


class AgentAuthMiddleware:
    def __init__(
        self,
        app,
        *,
        verifier: RequestVerifier,
        grants: Optional[GrantVerifier] = None,
        rules: Callable[[AgentRequest], Any] = lambda req: None,
        audit: Any = None,
        max_body_bytes: int = 1024 * 1024,
    ):
        self.app, self.verifier, self.grants, self.rules = app, verifier, grants, rules
        self.audit, self.max_body_bytes = audit, max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        chunks, size, more = [], 0, True
        while more:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return
            chunk = msg.get("body", b"")
            size += len(chunk)
            if size > self.max_body_bytes:
                return await _respond(send, 413, "request body too large")
            chunks.append(chunk)
            more = msg.get("more_body", False)
        body = b"".join(chunks)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        req = AgentRequest(scope["method"], scope.get("path", "/"), request_target(scope), headers, body)

        try:
            rule = self.rules(req)
        except RecursionError:
            return await _respond(send, 400, "request body is nested too deeply")
        except (ValueError, KeyError, TypeError) as e:
            return await _respond(send, 400, f"could not determine the authorization requirement: {e}")
        if rule is not PUBLIC:
            result = await self._authorize(req, rule, send)
            if result is None:
                return
            scope.setdefault("state", {})["agentauth"] = result

        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        return await self.app(scope, replay, send)

    async def _authorize(self, req: AgentRequest, rule: Any, send):
        grant_hdr = req.headers.get(GRANT_HEADER.lower(), "")
        try:
            agent = self.verifier.verify(authorization=req.headers.get("authorization", ""), method=req.method,
                                         path=req.target, body=req.body, grants=grant_hdr,
                                         host=req.headers.get("host"))
        except AuthError as e:
            extra = [(b"www-authenticate", b"AgentSig")] if e.status == 401 else []
            await _respond(send, e.status, str(e), extra)
            return None
        if rule is None:
            return agent
        if not isinstance(rule, Requirement):
            raise TypeError("rules() must return PUBLIC, None or a Requirement")
        if self.grants is None:
            raise RuntimeError("a Requirement needs a GrantVerifier")
        authz = None
        try:
            authz = self.grants.verify(grant_hdr, requester=agent.did, audience=agent.audience)
            missing = [s for s in rule.scopes if not authz.allows(s)]
            if missing:
                raise GrantError(f"grant does not cover: {', '.join(missing)}", 403)
            self.grants.enforce(authz, resource=rule.resource, amount=rule.amount, unit=rule.unit)
        except GrantError as e:
            self._audit(req, agent.did, rule, authz, "denied", e.status, str(e))
            await _respond(send, e.status, str(e))
            return None
        if not self._audit(req, agent.did, rule, authz, "allowed", 200, None):
            await _respond(send, 503, "audit log unavailable")
            return None
        return authz

    def _audit(self, req, did, rule, authz, outcome, status, reason) -> bool:
        """Returns False when an *allowed* decision couldn't be audited (the caller then refuses it)."""
        if self.audit is None:
            return True
        try:
            self.audit.record(agent=did, outcome=outcome, status=status, scopes=rule.scopes, authz=authz,
                              resource=rule.resource, amount=rule.amount, unit=rule.unit, reason=reason,
                              method=req.method, path=req.target, request_id=req.headers.get("x-request-id"))
            return True
        except Exception:
            log.exception("audit log write failed")
            if outcome == "allowed" and authz is not None and authz.charged:
                authz.refund()
            return outcome != "allowed"


# --------------------------------------------------------------------------- #
# MCP (Model Context Protocol) over streamable HTTP
# --------------------------------------------------------------------------- #


def mcp_rules(
    *,
    tool_scope_prefix: str = "mcp.tools.",
    session_scope: Optional[str] = "mcp.session",
    public_paths: tuple = (),
    resource: Optional[Callable[[str, dict], Optional[str]]] = None,
) -> Callable[[AgentRequest], Any]:
    """Rules for an MCP server's HTTP endpoint (JSON-RPC 2.0 over POST, SSE over GET).

    * Every request needs a grant covering `session_scope` (``mcp.session``),
      or just a valid signature if `session_scope` is None.
    * A ``tools/call`` additionally needs ``<tool_scope_prefix><tool name>``,
      e.g. ``mcp.tools.search``. A principal can grant ``mcp.tools.*`` for
      every tool. Batches need the scopes of every call in them.
    * `resource(tool_name, arguments)` may name the resource a call touches, so
      resource limits on grants apply to tools.

    Tool names are restricted to characters valid in a scope; a call to any
    other name is refused (fail closed).
    """

    def rules(req: AgentRequest) -> Any:
        if req.path in public_paths:
            return PUBLIC
        scopes = [session_scope] if session_scope else []
        res = None
        if req.method == "POST" and req.body:
            msg = req.json()
            calls = msg if isinstance(msg, list) else [msg]
            for c in calls:
                if not isinstance(c, dict):
                    raise ValueError("JSON-RPC messages must be objects")
                if c.get("method") == "tools/call":
                    params = c.get("params") or {}
                    name = params.get("name") if isinstance(params, dict) else None
                    if not isinstance(name, str) or not name or len(name) > 100 or \
                            any(not (ch.isalnum() or ch in "_-.") for ch in name):
                        raise ValueError("tools/call needs a tool name made of letters, digits, '_', '-' or '.'")
                    scopes.append(tool_scope_prefix + name)
                    if resource is not None:
                        r = resource(name, params.get("arguments") or {})
                        if r is not None:
                            if res is not None and r != res:
                                raise ValueError("a batch may touch at most one resource")
                            res = r
        if not scopes:
            return None
        return Requirement(scopes=scopes, resource=res)

    return rules

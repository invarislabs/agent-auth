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
``request.state.agentauth``) as a `VerifiedAgent` or `AuthorizedAgent`, and
``scope["user"]`` is set to an authenticated `AgentUser` (its ``identity`` is
the DID), so frameworks that key sessions or permissions on the user see the
agent.

The request body is buffered (it's covered by the signature) up to
`max_body_bytes`, then replayed to the app unchanged.

Security notes:

* ``req.path`` is the path *relative to the app the middleware wraps* (the
  mount prefix, ``root_path``, is removed), i.e. what the app routes on;
  ``req.full_path`` keeps the prefix. Write rules deny-by-default: return a
  Requirement unless a path is known to need less.
* WebSocket connections go through ``rules`` too (``req.websocket`` is True,
  method ``GET``, empty body). Unless the rule is PUBLIC, the handshake must
  carry a valid AgentSig signature (and grant), or the connection is closed
  with code 1008 before the app sees it. Lifespan events pass through; any
  other ASGI scope type is refused.
* A request with more than one Authorization, Host or AgentGrant header is
  refused: different components could otherwise read different values.
* MCP sessions (``Mcp-Session-Id``) are bound to the DID that opened them;
  another agent presenting the same session id is refused (403). The binding
  is per process: with several workers, use sticky sessions or a shared
  session store in the MCP server itself.
"""

from __future__ import annotations

import json
import logging
import threading
from collections import OrderedDict
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
    path: str  # decoded path relative to the wrapped app (mount prefix removed), for routing decisions
    target: str  # raw path + query, exactly as signed
    headers: dict
    body: bytes
    full_path: str = ""  # decoded path including any mount prefix (root_path)
    websocket: bool = False

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


class AgentUser:
    """``scope["user"]`` for an authenticated agent (duck-compatible with Starlette's BaseUser)."""

    def __init__(self, did: str, scopes: Optional[list] = None):
        self.did, self.scopes = did, list(scopes or [])

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def display_name(self) -> str:
        return self.did

    @property
    def identity(self) -> str:
        return self.did

    def __repr__(self) -> str:
        return f"AgentUser({self.did!r})"


_SINGLE_HEADERS = (b"authorization", b"host", GRANT_HEADER.lower().encode())


def _route_path(scope: Any) -> tuple:
    """(path relative to the wrapped app, full path)."""
    full = scope.get("path", "/") or "/"
    root = (scope.get("root_path") or "").rstrip("/")
    if root and (full == root or full.startswith(root + "/")):
        return full[len(root):] or "/", full
    return full, (root + full if root and not full.startswith(root) else full)


class _Deny(Exception):
    def __init__(self, status: int, detail: str, headers: Optional[list] = None):
        super().__init__(detail)
        self.status, self.detail, self.headers = status, detail, headers or []


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
        session_header: Optional[str] = "mcp-session-id",
        max_sessions: int = 100_000,
    ):
        self.app, self.verifier, self.grants, self.rules = app, verifier, grants, rules
        self.audit, self.max_body_bytes = audit, max_body_bytes
        self.session_header = session_header.lower().encode() if session_header else None
        self.max_sessions = max_sessions
        self._sessions: OrderedDict = OrderedDict()  # session id -> DID that opened it
        self._sessions_lock = threading.Lock()

    def _headers(self, scope) -> dict:
        single = _SINGLE_HEADERS + ((self.session_header,) if self.session_header else ())
        seen: dict = {}
        for k, v in scope.get("headers", []):
            k = k.lower()
            if k in seen and k in single:
                raise _Deny(400, f"duplicate {k.decode('latin-1')} header")
            seen[k] = v
        return {k.decode("latin-1"): v.decode("latin-1") for k, v in seen.items()}

    def _check_session(self, headers: dict, did: Optional[str]) -> None:
        if self.session_header is None:
            return
        sid = headers.get(self.session_header.decode())
        if not sid:
            return
        with self._sessions_lock:
            owner = self._sessions.get(sid)
            if owner is not None:
                self._sessions.move_to_end(sid)  # in use: keep it bound
        if owner is not None and owner != did:
            raise _Deny(403, "this session belongs to a different agent")

    def _wrap_send(self, send, did: Optional[str], headers: dict):
        # Only a response to a request that carried *no* session id can open (and so bind) a
        # session. A request presenting an id it doesn't own must never get it bound to itself.
        if self.session_header is None or did is None or headers.get(self.session_header.decode()):
            return send

        async def wrapped(message):
            if message.get("type") == "http.response.start":
                for k, v in message.get("headers", []):
                    if k.lower() == self.session_header:
                        sid = v.decode("latin-1")
                        with self._sessions_lock:
                            self._sessions.setdefault(sid, did)
                            self._sessions.move_to_end(sid)
                            while len(self._sessions) > self.max_sessions:
                                self._sessions.popitem(last=False)
            await send(message)

        return wrapped

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)
        if scope["type"] == "websocket":
            return await self._websocket(scope, receive, send)
        if scope["type"] != "http":
            log.warning("refusing unknown ASGI scope type %r", scope["type"])
            return

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
        try:
            headers = self._headers(scope)
            path, full = _route_path(scope)
            req = AgentRequest(scope["method"], path, request_target(scope), headers, body, full_path=full)
            rule = self._rule(req)
            did = None
            if rule is not PUBLIC:
                result = self._authorize(req, rule)
                did = result.did
                self._attach(scope, result, did)
            else:
                self._check_session(headers, None)
        except _Deny as e:
            return await _respond(send, e.status, e.detail, e.headers)

        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        return await self.app(scope, replay, self._wrap_send(send, did, headers))

    def _rule(self, req: AgentRequest) -> Any:
        try:
            return self.rules(req)
        except RecursionError:
            raise _Deny(400, "request body is nested too deeply") from None
        except (ValueError, KeyError, TypeError) as e:
            raise _Deny(400, f"could not determine the authorization requirement: {e}") from None

    @staticmethod
    def _attach(scope, result, did: str) -> None:
        scope.setdefault("state", {})["agentauth"] = result
        scope["user"] = AgentUser(did, getattr(result, "scopes", None))
        try:  # Starlette's request.auth, when Starlette is installed
            from starlette.authentication import AuthCredentials

            scope["auth"] = AuthCredentials(list(getattr(result, "scopes", []) or []))
        except ImportError:  # pragma: no cover - starlette is optional
            pass

    async def _websocket(self, scope, receive, send):
        async def close(code: int = 1008):
            # Consume the connect event, then refuse the handshake (the app never sees it).
            msg = await receive()
            if msg.get("type") == "websocket.connect":
                await send({"type": "websocket.close", "code": code})

        try:
            headers = self._headers(scope)
            path, full = _route_path(scope)
            req = AgentRequest("GET", path, request_target(scope), headers, b"", full_path=full, websocket=True)
            rule = self._rule(req)
            if rule is not PUBLIC:
                result = self._authorize(req, rule)
                self._attach(scope, result, result.did)
            else:
                self._check_session(headers, None)
        except _Deny as e:
            log.info("websocket refused: %s", e.detail)
            return await close()
        return await self.app(scope, receive, send)

    def _authorize(self, req: AgentRequest, rule: Any):
        """Verify the request; returns the VerifiedAgent/AuthorizedAgent or raises _Deny."""
        grant_hdr = req.headers.get(GRANT_HEADER.lower(), "")
        try:
            agent = self.verifier.verify(authorization=req.headers.get("authorization", ""), method=req.method,
                                         path=req.target, body=req.body, grants=grant_hdr,
                                         host=req.headers.get("host"))
        except AuthError as e:
            extra = [(b"www-authenticate", b"AgentSig")] if e.status == 401 else []
            raise _Deny(e.status, str(e), extra) from None
        # Session ownership is checked before any grant is charged or any decision audited.
        self._check_session(req.headers, agent.did)
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
            raise _Deny(e.status, str(e)) from None
        if not self._audit(req, agent.did, rule, authz, "allowed", 200, None):
            raise _Deny(503, "audit log unavailable")
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

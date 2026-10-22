"""AgentAuth registry: stores key event logs and resolves agent DIDs.

The registry is a *witness*, not an authority: it validates every event before
accepting it, but it cannot forge events, and any client can re-verify the
full log it serves (GET /v1/identities/{did}/log).

Run it with ``agentauth serve`` or any ASGI server::

    uvicorn agentauth.server:get_app --factory

Configuration comes from ``AGENTAUTH_*`` environment variables (see
`agentauth.config.Settings` and docs/operations.md).
"""

from __future__ import annotations

import contextlib
import hmac
import json
import logging
import re
import time
import uuid
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
from .config import Settings
from .grants import GrantError, verify_revocation
from .httpsig import NonceCache, RequestVerifier, VerifiedAgent
from .identity import InvalidEvent, apply_event, is_agent_did, verify_inception
from .integrations import fastapi_dependency
from .observability import Counter, Gauge, Histogram, Registry, configure_logging
from .ratelimit import MemoryRateLimiter, RedisRateLimiter
from .store import Conflict, SchemaError, open_store

MAX_EVENT_BYTES = 16 * 1024
MAX_CHECK_PAIRS = 32
REGISTRATION_TOKEN_HEADER = "X-AgentAuth-Registration-Token"  # noqa: S105  # nosec B105
_REQUEST_ID_RE = re.compile(r"\A[A-Za-z0-9_\-.]{1,64}\Z")
_GRANT_ID_RE = re.compile(r"\A[A-Za-z0-9_\-.:]{1,128}\Z")  # same rule as grants._ID_RE

log = logging.getLogger("agentauth.registry")
access_log = logging.getLogger("agentauth.access")


def _log_safe(value: Any) -> str:
    """Strip line breaks from client-supplied values before logging them (no forged log lines)."""
    return str(value).replace("\r", "").replace("\n", "")[:256]


def _strict_json(raw: bytes) -> Any:
    """Parse JSON, rejecting NaN/Infinity and duplicate object keys."""

    def no_dupes(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise ValueError(f"duplicate key {k!r}")
            d[k] = v
        return d

    def no_constants(name):
        raise ValueError(f"{name} is not valid JSON")

    return json.loads(raw, object_pairs_hook=no_dupes, parse_constant=no_constants)


class _BodyLimit:
    """ASGI middleware: refuse request bodies larger than `limit` bytes, before the app reads them."""

    def __init__(self, app, limit: int):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        for k, v in scope.get("headers", []):
            if k == b"content-length":
                try:
                    too_big = int(v) > self.limit
                except ValueError:
                    too_big = True
                if too_big:
                    return await _send_json(send, 413, {"detail": "request body too large"})
        chunks, size, more = [], 0, True
        while more:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return
            body = msg.get("body", b"")
            size += len(body)
            if size > self.limit:
                return await _send_json(send, 413, {"detail": "request body too large"})
            chunks.append(body)
            more = msg.get("more_body", False)
        buffered = b"".join(chunks)
        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": buffered, "more_body": False}
            return await receive()

        return await self.app(scope, replay, send)


async def _send_json(send, status: int, obj: dict) -> None:
    body = json.dumps(obj).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


def create_app(
    db_path: Optional[str] = None,
    audiences: Optional[set] = None,
    *,
    settings: Optional[Settings] = None,
    store=None,
) -> FastAPI:
    """Build the registry app.

    `db_path` and `audiences` are kept for compatibility; they override the
    corresponding `settings` fields. Pass `store` to supply an already-open
    store (tests, embedding).
    """
    settings = settings or Settings.from_env()
    if db_path is not None:
        settings.database_url = db_path
    if audiences is not None:
        settings.audiences = {a.lower() for a in audiences}
    settings.validate()

    store = store or open_store(settings.database_url, auto_migrate=settings.auto_migrate)

    redis_client = None
    if settings.redis_url:
        from .backends.redis import RedisNonceCache, _client

        redis_client = _client(settings.redis_url)
        nonce_cache: Any = RedisNonceCache(redis_client, ttl=2 * settings.max_skew + 1, prefix="agentauth:registry:")
        limiter: Any = RedisRateLimiter(redis_client)
    else:
        nonce_cache = NonceCache(ttl=2 * settings.max_skew + 1)
        limiter = MemoryRateLimiter()

    # -- metrics ----------------------------------------------------------- #
    metrics = Registry()
    m_requests = metrics.add(Counter("agentauth_http_requests_total", "HTTP requests", ("method", "route", "status")))
    m_latency = metrics.add(Histogram("agentauth_http_request_duration_seconds", "HTTP request latency", ("route",)))
    m_events = metrics.add(Counter("agentauth_registry_events_total", "Key events submitted", ("type", "outcome")))
    m_revocations = metrics.add(Counter("agentauth_registry_revocations_total", "Revocations submitted", ("outcome",)))
    m_ratelimited = metrics.add(Counter("agentauth_http_rate_limited_total", "Requests refused by rate limiting", ("kind",)))
    m_info = metrics.add(Counter("agentauth_build_info", "Build information", ("version",)))
    m_info.inc(__version__)

    @contextlib.asynccontextmanager
    async def lifespan(app):
        log.info("registry starting", extra={"settings": settings.describe(), "version": __version__})
        yield
        log.info("registry stopping")
        store.close()

    app = FastAPI(title="AgentAuth Registry", version=__version__, lifespan=lifespan)
    app.state.store = store
    app.state.settings = settings
    app.state.metrics = metrics

    stats_cache: dict = {"at": 0.0, "value": {}}

    def _stat(name: str) -> float:
        if time.time() - stats_cache["at"] > 15:
            stats_cache["value"], stats_cache["at"] = store.stats(), time.time()
        return stats_cache["value"].get(name, 0)

    metrics.add(Gauge("agentauth_registry_identities", "Registered identities", lambda: _stat("identities")))
    metrics.add(Gauge("agentauth_registry_active_identities", "Active identities", lambda: _stat("active")))
    metrics.add(Gauge("agentauth_registry_stored_revocations", "Stored grant revocations", lambda: _stat("revocations")))

    # -- helpers ----------------------------------------------------------- #

    def current_key(did: str) -> Optional[tuple]:
        st = store.get_state(did)
        if st is None or not st.active or not st.key:
            return None
        return st.key, st.key_id

    def controller_is_current(did: str, key: str) -> bool:
        found = current_key(did)
        return found is not None and found[0] == key

    verifier = RequestVerifier(resolve_key=current_key, audiences=settings.audiences,
                               max_skew=settings.max_skew, nonce_cache=nonce_cache)
    app.state.verifier = verifier

    async def read_json(request: Request) -> Any:
        raw = await request.body()
        if len(raw) > min(MAX_EVENT_BYTES, settings.max_body_bytes):
            raise HTTPException(413, "event too large")
        try:
            return _strict_json(raw)
        except (ValueError, RecursionError) as e:
            raise HTTPException(400, f"body must be JSON: {e}") from None

    async def read_event(request: Request) -> dict:
        ev = await read_json(request)
        if not isinstance(ev, dict) or not isinstance(ev.get("body"), dict):
            raise HTTPException(400, "expected a signed event {body, signer, sig}")
        return ev

    def check_did(did: str) -> None:
        if not is_agent_did(did):
            raise HTTPException(404, "unknown identity (not a did:agent identifier)")

    def page_args(limit: int, after: str) -> tuple:
        if not 1 <= limit <= 1000:
            raise HTTPException(400, "limit must be between 1 and 1000")
        if after and not is_agent_did(after):
            raise HTTPException(400, "after must be a DID from a previous page")
        return limit, after

    authenticated_agent = fastapi_dependency(verifier)

    # -- middleware: request id, access log, metrics, rate limits ---------- #

    def client_ip(request: Request) -> str:
        if settings.trusted_proxy_hops:
            xff = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
            if len(xff) >= settings.trusted_proxy_hops:
                return xff[-settings.trusted_proxy_hops]
        return request.client.host if request.client else "unknown"

    @app.middleware("http")
    async def observe(request: Request, call_next):
        rid = request.headers.get("x-request-id", "")
        if not _REQUEST_ID_RE.match(rid):
            rid = uuid.uuid4().hex
        request.state.request_id = rid
        start = time.perf_counter()
        ip = client_ip(request)
        path = request.url.path
        if path.startswith("/v1/"):
            write = request.method in ("POST", "PUT", "PATCH", "DELETE") and path != "/v1/revocations/check"
            rule = settings.rate_limit_writes if write else settings.rate_limit_reads
            if rule:
                ok, retry = limiter.hit(f"{'w' if write else 'r'}:{ip}", *rule)
                if not ok:
                    m_ratelimited.inc("write" if write else "read")
                    resp = JSONResponse({"detail": "rate limit exceeded"}, status_code=429,
                                        headers={"Retry-After": str(retry), "X-Request-ID": rid})
                    access_log.info("request", extra={"request_id": rid, "method": request.method, "path": path,
                                                      "status": 429, "client": ip, "duration_ms": 0})
                    return resp
        try:
            response = await call_next(request)
        except Exception:
            log.exception("unhandled error", extra={"request_id": rid, "path": path})
            response = JSONResponse({"detail": "internal error", "request_id": rid}, status_code=500)
        elapsed = time.perf_counter() - start
        route = getattr(request.scope.get("route"), "path", "unmatched")
        m_requests.inc(request.method, route, str(response.status_code))
        m_latency.observe(elapsed, route)
        response.headers["X-Request-ID"] = rid
        if route not in ("/healthz", "/readyz", "/metrics"):
            access_log.info("request", extra={
                "request_id": rid, "method": request.method, "path": path, "route": route,
                "status": response.status_code, "client": ip, "duration_ms": round(elapsed * 1000, 2),
            })
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        return JSONResponse({"detail": "invalid request parameters"}, status_code=400)

    # -- routes: operations ------------------------------------------------ #

    @app.get("/healthz")
    def healthz():
        """Liveness: the process is up and serving."""
        return {"ok": True}

    @app.get("/readyz")
    def readyz():
        """Readiness: the database (and Redis, if configured) answer and the schema is current."""
        checks: dict = {}
        try:
            store.ping()
            store.check_schema()
            checks["database"] = "ok"
        except SchemaError as e:
            # Details go to the log, not to unauthenticated callers.
            log.warning("readiness: %s", e)
            checks["database"] = "schema not current"
        except Exception as e:
            log.warning("readiness: database check failed: %s", type(e).__name__)
            checks["database"] = "unavailable"
        if redis_client is not None:
            try:
                redis_client.ping()
                checks["redis"] = "ok"
            except Exception as e:
                log.warning("readiness: redis check failed: %s", type(e).__name__)
                checks["redis"] = "unavailable"
        ok = all(v == "ok" for v in checks.values())
        return JSONResponse({"ok": ok, "checks": checks}, status_code=200 if ok else 503)

    if settings.metrics_enabled:
        @app.get("/metrics")
        def metrics_endpoint():
            return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")

    @app.get("/v1/info")
    def info():
        return {
            "software": "agentauth-registry",
            "version": __version__,
            "protocols": {"identity": "agentauth/1", "request": "agentauth-request/1",
                          "grant": "agentauth-grant/1", "revocation": "agentauth-revocation/1"},
            "schema_version": store.schema_version(),
            "registration": "token" if settings.registration_token else "open",
            "max_event_bytes": MAX_EVENT_BYTES,
        }

    # -- routes: identities ------------------------------------------------ #

    @app.post("/v1/identities", status_code=201)
    async def register(request: Request):
        if settings.registration_token:
            presented = request.headers.get(REGISTRATION_TOKEN_HEADER, "")
            if not hmac.compare_digest(presented.encode(), settings.registration_token.encode()):
                m_events.inc("inception", "unauthorized")
                raise HTTPException(401, "registration requires a valid registration token")
        event = await read_event(request)
        try:
            state = verify_inception(event, controller_is_current)
        except InvalidEvent as e:
            m_events.inc("inception", "invalid")
            raise HTTPException(400, str(e)) from None
        if state.controller and current_key(state.controller) is None:
            m_events.inc("inception", "invalid")
            raise HTTPException(400, "controller is not a registered, active identity")
        try:
            store.append(event, state, expected_prev_seq=None)
        except Conflict:
            m_events.inc("inception", "conflict")
            raise HTTPException(409, "identity already registered") from None
        m_events.inc("inception", "accepted")
        log.info("identity registered", extra={"did": _log_safe(state.did), "controller": _log_safe(state.controller)})
        return state.resolution_result()

    @app.get("/v1/identities")
    def list_identities(after: str = "", limit: int = 100):
        """Page through every registered DID (for mirrors, witnesses and audits)."""
        limit, after = page_args(limit, after)
        rows = store.list_dids(after=after, limit=limit)
        return {"identities": rows, "next": rows[-1]["did"] if len(rows) == limit else None}

    @app.post("/v1/identities/{did}/events")
    async def append_event(did: str, request: Request):
        check_did(did)
        event = await read_event(request)
        etype = event["body"].get("type") if isinstance(event["body"].get("type"), str) else "unknown"
        etype = etype if etype in ("rotation", "deactivation") else "unknown"
        state = store.get_state(did)
        if state is None:
            raise HTTPException(404, "unknown identity")
        try:
            new_state = apply_event(state, event, controller_is_current)
        except InvalidEvent as e:
            m_events.inc(etype, "invalid")
            raise HTTPException(400, str(e)) from None
        try:
            store.append(event, new_state, expected_prev_seq=state.seq)
        except Conflict:
            m_events.inc(etype, "conflict")
            raise HTTPException(409, "concurrent update; fetch the log and retry") from None
        m_events.inc(etype, "accepted")
        log.info("key event accepted", extra={"did": _log_safe(did), "type": _log_safe(etype), "seq": new_state.seq})
        return new_state.resolution_result()

    @app.get("/v1/identities/{did}")
    def resolve(did: str):
        check_did(did)
        state = store.get_state(did)
        if state is None:
            raise HTTPException(404, "unknown identity")
        headers = {"Cache-Control": f"max-age={settings.resolve_cache_seconds}"}
        return JSONResponse(state.resolution_result(), headers=headers)

    @app.get("/v1/identities/{did}/log")
    def get_log(did: str):
        check_did(did)
        events = store.get_log(did)
        if not events:
            raise HTTPException(404, "unknown identity")
        return {"did": did, "events": events}

    @app.get("/v1/identities/{did}/agents")
    def controlled_agents(did: str, after: str = "", limit: int = 1000):
        """Agents whose controller is `did` (e.g. every agent a human owns)."""
        check_did(did)
        limit, after = page_args(limit, after)
        rows = store.list_by_controller(did, limit=limit, after=after)
        return {"controller": did, "agents": rows, "next": rows[-1]["did"] if len(rows) == limit else None}

    # -- routes: revocations ----------------------------------------------- #

    @app.post("/v1/revocations", status_code=201)
    async def revoke_grant(request: Request):
        """Record that an issuer revoked one of its grants (and so every delegation beneath it)."""
        event = await read_event(request)
        iss = event["body"].get("iss")
        found = current_key(iss) if is_agent_did(iss) else None
        if found is None:
            m_revocations.inc("invalid")
            raise HTTPException(400, "issuer is unknown or deactivated")
        try:
            body = verify_revocation(event, found[0])
        except GrantError as e:
            m_revocations.inc("invalid")
            raise HTTPException(e.status, str(e)) from None
        created = store.add_revocation(body["iss"], body["grant"], body["ts"], event)
        m_revocations.inc("accepted" if created else "duplicate")
        log.info("grant revoked", extra={"issuer": _log_safe(body["iss"]), "grant": _log_safe(body["grant"]),
                                         "new": created})
        return {"issuer": body["iss"], "grant": body["grant"], "revoked": True, "new": created}

    @app.post("/v1/revocations/check")
    async def check_revocations(request: Request):
        """Body: {"grants": [[issuer, grant_id], ...]} → the subset that is revoked, with signed proofs."""
        data = await read_json(request)
        pairs = data.get("grants") if isinstance(data, dict) else None
        if (
            not isinstance(pairs, list)
            or len(pairs) > MAX_CHECK_PAIRS
            or not all(isinstance(p, list) and len(p) == 2 and is_agent_did(p[0])
                       and isinstance(p[1], str) and _GRANT_ID_RE.match(p[1]) for p in pairs)
        ):
            raise HTTPException(400, f'expected {{"grants": [[issuer, grant_id], ...]}} (max {MAX_CHECK_PAIRS})')
        found = store.revocation_events([(a, b) for a, b in pairs])
        revoked = [[a, b] for a, b in pairs if (a, b) in found]
        return {"revoked": revoked, "proofs": [found[(a, b)] for a, b in revoked]}

    @app.get("/v1/whoami")
    def whoami(agent: VerifiedAgent = Depends(authenticated_agent)):
        return {"did": agent.did, "kid": agent.kid}

    # Outermost layer: oversized bodies are refused before anything reads them.
    app.add_middleware(_BodyLimit, limit=settings.max_body_bytes)
    return app


def get_app() -> FastAPI:  # for `uvicorn agentauth.server:get_app --factory`
    settings = Settings.from_env()
    configure_logging(settings.log_level, settings.log_format)
    return create_app(settings=settings)

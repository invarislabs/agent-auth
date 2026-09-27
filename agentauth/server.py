"""AgentAuth registry: stores key event logs and resolves agent DIDs.

The registry is a *witness*, not an authority: it validates every event before
accepting it, but it cannot forge events, and any client can re-verify the
full log it serves (GET /v1/identities/{did}/log).
"""

from __future__ import annotations

import json
import os
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .grants import GrantError, verify_revocation
from .httpsig import RequestVerifier, VerifiedAgent
from .integrations import fastapi_dependency
from .identity import InvalidEvent, apply_event, verify_inception
from .store import Conflict, Store

MAX_EVENT_BYTES = 16 * 1024


def create_app(db_path: Optional[str] = None, audiences: Optional[set] = None) -> FastAPI:
    db_path = db_path or os.environ.get("AGENTAUTH_DB", "agentauth.db")
    if audiences is None:
        env = os.environ.get("AGENTAUTH_AUDIENCES", "localhost:8000,127.0.0.1:8000")
        audiences = {a.strip() for a in env.split(",") if a.strip()}

    store = Store(db_path)
    app = FastAPI(title="AgentAuth Registry", version="0.3.0")
    app.state.store = store

    # -- helpers ----------------------------------------------------------- #

    def current_key(did: str) -> Optional[tuple]:
        st = store.get_state(did)
        if st is None or not st.active or not st.key:
            return None
        return st.key, st.key_id

    def controller_is_current(did: str, key: str) -> bool:
        found = current_key(did)
        return found is not None and found[0] == key

    verifier = RequestVerifier(resolve_key=current_key, audiences=audiences)
    app.state.verifier = verifier

    async def read_event(request: Request) -> dict:
        raw = await request.body()
        if len(raw) > MAX_EVENT_BYTES:
            raise HTTPException(413, "event too large")
        try:
            ev = json.loads(raw)
        except ValueError:
            raise HTTPException(400, "body must be JSON") from None
        if not isinstance(ev, dict) or not isinstance(ev.get("body"), dict):
            raise HTTPException(400, "expected a signed event {body, signer, sig}")
        return ev

    authenticated_agent = fastapi_dependency(verifier)

    # -- routes ------------------------------------------------------------ #

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.post("/v1/identities", status_code=201)
    async def register(request: Request):
        event = await read_event(request)
        try:
            state = verify_inception(event, controller_is_current)
        except InvalidEvent as e:
            raise HTTPException(400, str(e)) from None
        if state.controller and current_key(state.controller) is None:
            raise HTTPException(400, "controller is not a registered, active identity")
        try:
            store.append(event, state, expected_prev_seq=None)
        except Conflict:
            raise HTTPException(409, "identity already registered") from None
        return state.resolution_result()

    @app.post("/v1/identities/{did}/events")
    async def append_event(did: str, request: Request):
        event = await read_event(request)
        state = store.get_state(did)
        if state is None:
            raise HTTPException(404, "unknown identity")
        try:
            new_state = apply_event(state, event, controller_is_current)
        except InvalidEvent as e:
            raise HTTPException(400, str(e)) from None
        try:
            store.append(event, new_state, expected_prev_seq=state.seq)
        except Conflict:
            raise HTTPException(409, "concurrent update; fetch the log and retry") from None
        return new_state.resolution_result()

    @app.get("/v1/identities/{did}")
    def resolve(did: str):
        state = store.get_state(did)
        if state is None:
            raise HTTPException(404, "unknown identity")
        headers = {"Cache-Control": "max-age=30"}
        return JSONResponse(state.resolution_result(), headers=headers)

    @app.get("/v1/identities/{did}/log")
    def log(did: str):
        events = store.get_log(did)
        if not events:
            raise HTTPException(404, "unknown identity")
        return {"did": did, "events": events}

    @app.get("/v1/identities/{did}/agents")
    def controlled_agents(did: str):
        """Agents whose controller is `did` (e.g. every agent a human owns)."""
        return {"controller": did, "agents": store.list_by_controller(did)}

    @app.post("/v1/revocations", status_code=201)
    async def revoke_grant(request: Request):
        """Record that an issuer revoked one of its grants (and so every delegation beneath it)."""
        event = await read_event(request)
        iss = event["body"].get("iss")
        found = current_key(iss) if isinstance(iss, str) else None
        if found is None:
            raise HTTPException(400, "issuer is unknown or deactivated")
        try:
            body = verify_revocation(event, found[0])
        except GrantError as e:
            raise HTTPException(e.status, str(e)) from None
        created = store.add_revocation(body["iss"], body["grant"], body["ts"], event)
        return {"issuer": body["iss"], "grant": body["grant"], "revoked": True, "new": created}

    @app.post("/v1/revocations/check")
    async def check_revocations(request: Request):
        """Body: {"grants": [[issuer, grant_id], ...]} → the subset that is revoked."""
        try:
            pairs = (await request.json())["grants"]
            assert isinstance(pairs, list) and len(pairs) <= 32
            pairs = [(str(a), str(b)) for a, b in pairs]
        except Exception:
            raise HTTPException(400, 'expected {"grants": [[issuer, grant_id], ...]} (max 32)') from None
        return {"revoked": store.revoked_among(pairs)}

    @app.get("/v1/whoami")
    def whoami(agent: VerifiedAgent = Depends(authenticated_agent)):
        return {"did": agent.did, "kid": agent.kid}

    return app


def get_app() -> FastAPI:  # for `uvicorn agentauth.server:get_app --factory`
    return create_app()

"""ASGI middleware, MCP tool scopes, encoded request paths and the audit log."""

import json
import sqlite3

import pytest
from conftest import make_registry
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from agentauth import (
    AgentIdentity,
    AuditLog,
    GrantVerifier,
    KeyPair,
    Limits,
    RegistryKeyResolver,
    RequestVerifier,
    trust_principals,
)
from agentauth.asgi import PUBLIC, AgentAuthMiddleware, Requirement, mcp_rules, request_target
from agentauth.integrations import fastapi_authorizer, fastapi_dependency

SVC = "svc.example"


@pytest.fixture
def w():
    reg, _ = make_registry()

    def new(name):
        ident, ev = AgentIdentity.create(name=name)
        reg.register(ev)
        return ident

    human, agent = new("human"), new("agent")
    keys = RegistryKeyResolver(reg, ttl=30)
    return dict(reg=reg, human=human, agent=agent, keys=keys)


# --------------------------------------------------------------------------- #
# request target (regression: v0.3 verified the *decoded* path)
# --------------------------------------------------------------------------- #


def test_request_target_uses_raw_path():
    assert request_target({"raw_path": b"/a%20b/c%2Fd", "path": "/a b/c/d", "query_string": b"x=1%202"}) == \
        "/a%20b/c%2Fd?x=1%202"
    assert request_target({"path": "/plain", "query_string": b""}) == "/plain"


def test_fastapi_accepts_percent_encoded_paths(w):
    app = FastAPI()
    dep = fastapi_dependency(RequestVerifier(w["keys"], audiences={SVC}))

    @app.get("/files/{name:path}")
    def get(name: str, a=Depends(dep)):
        return {"name": name}

    c = TestClient(app, base_url=f"http://{SVC}")
    r = c.get("/files/q3%20report.pdf?v=a%2Fb", auth=w["agent"].httpx_auth())
    assert r.status_code == 200, r.text
    assert r.json() == {"name": "q3 report.pdf"}


# --------------------------------------------------------------------------- #
# generic ASGI middleware
# --------------------------------------------------------------------------- #


def _starlette():
    async def whoami(request):
        a = request.state.agentauth
        return JSONResponse({"did": a.did, "principal": getattr(a, "principal", None)})

    async def health(request):
        return JSONResponse({"ok": True})

    async def echo(request):
        return JSONResponse({"len": len(await request.body())})

    return Starlette(routes=[Route("/whoami", whoami), Route("/health", health), Route("/echo", echo, methods=["POST"])])


def test_middleware_rules(w):
    def rules(req):
        if req.path == "/health":
            return PUBLIC
        if req.path == "/echo":
            return Requirement(scopes=["tools.echo"])
        return None

    app = AgentAuthMiddleware(
        _starlette(),
        verifier=RequestVerifier(w["keys"], audiences={SVC}),
        grants=GrantVerifier(w["keys"], trust_principals({w["human"].did: ["tools.*"]})),
        rules=rules,
        max_body_bytes=1000,
    )
    c = TestClient(app, base_url=f"http://{SVC}")
    assert c.get("/health").json() == {"ok": True}
    r = c.get("/whoami")
    assert r.status_code == 401 and r.headers["www-authenticate"] == "AgentSig"
    assert c.get("/whoami", auth=w["agent"].httpx_auth()).json()["did"] == w["agent"].did
    assert c.post("/echo", content=b"hi", auth=w["agent"].httpx_auth()).status_code == 401  # no grant
    g = w["human"].grant(w["agent"].did, ["tools.echo"], [SVC])
    r = c.post("/echo", content=b"hello", auth=w["agent"].httpx_auth(g))
    assert r.json() == {"len": 5}  # body was replayed intact to the app
    assert c.post("/echo", content=b"x" * 2000, auth=w["agent"].httpx_auth(g)).status_code == 413
    other = w["human"].grant(w["agent"].did, ["tools.other"], [SVC])
    assert c.post("/echo", content=b"x", auth=w["agent"].httpx_auth(other)).status_code == 403


# --------------------------------------------------------------------------- #
# MCP
# --------------------------------------------------------------------------- #


def _rpc(method, params=None, id=1):
    return {"jsonrpc": "2.0", "id": id, "method": method, "params": params or {}}


def test_mcp_rules_unit():
    from agentauth.asgi import AgentRequest

    rules = mcp_rules(resource=lambda name, args: args.get("path"))

    def req(body, method="POST"):
        return AgentRequest(method, "/mcp", "/mcp", {}, json.dumps(body).encode() if body is not None else b"")

    assert rules(req(_rpc("tools/list"))).scopes == ["mcp.session"]
    r = rules(req(_rpc("tools/call", {"name": "read_file", "arguments": {"path": "/r/q3"}})))
    assert r.scopes == ["mcp.session", "mcp.tools.read_file"] and r.resource == "/r/q3"
    batch = [_rpc("tools/call", {"name": "a"}, 1), _rpc("tools/call", {"name": "b"}, 2)]
    assert rules(req(batch)).scopes == ["mcp.session", "mcp.tools.a", "mcp.tools.b"]
    assert rules(req(None, method="GET")).scopes == ["mcp.session"]
    for bad in (_rpc("tools/call", {"name": "../x"}), _rpc("tools/call", {"name": ""}), _rpc("tools/call", {}),
                [1], _rpc("tools/call", {"name": "a b"})):
        with pytest.raises(ValueError):
            rules(req(bad))


def test_real_mcp_server_behind_middleware(w):
    mcp_server = pytest.importorskip("mcp.server.mcpserver")
    server = mcp_server.MCPServer("demo")

    @server.tool()
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b

    @server.tool()
    def wipe() -> str:
        """Dangerous."""
        return "wiped"

    aud = "127.0.0.1:8000"
    keys = w["keys"]
    audit = AuditLog()
    app = AgentAuthMiddleware(
        server.streamable_http_app(json_response=True, stateless_http=True),
        verifier=RequestVerifier(keys, audiences={aud}),
        grants=GrantVerifier(keys, trust_principals({w["human"].did: ["mcp.*"]})),
        rules=mcp_rules(),
        audit=audit,
    )
    g = w["human"].grant(w["agent"].did, ["mcp.session", "mcp.tools.add"], [aud], limits=Limits.build(uses=10))
    hdr = {"accept": "application/json, text/event-stream", "mcp-protocol-version": "2025-06-18"}
    with TestClient(app, base_url=f"http://{aud}") as c:
        def call(body, grant=g):
            return c.post("/mcp", json=body, headers=hdr, auth=w["agent"].httpx_auth(grant))

        assert c.post("/mcp", json=_rpc("tools/list"), headers=hdr).status_code == 401
        init = call(_rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                        "clientInfo": {"name": "t", "version": "1"}}))
        assert init.status_code == 200, init.text
        r = call(_rpc("tools/call", {"name": "add", "arguments": {"a": 2, "b": 3}}, 2))
        assert r.status_code == 200 and r.json()["result"]["structuredContent"] == {"result": 5}
        r = call(_rpc("tools/call", {"name": "wipe", "arguments": {}}, 3))
        assert r.status_code == 403 and "mcp.tools.wipe" in r.json()["detail"]
    outcomes = [e["body"]["outcome"] for e in audit.entries()]
    assert outcomes == ["allowed", "allowed", "denied"] and audit.verify() == []


# --------------------------------------------------------------------------- #
# audit log
# --------------------------------------------------------------------------- #


def test_audit_chain_and_tamper_detection(tmp_path):
    key = KeyPair.generate()
    path = str(tmp_path / "audit.db")
    log = AuditLog(path, signer=key, instance="svc-1")
    for i in range(5):
        log.record(agent=f"did:agent:{i}", outcome="allowed" if i % 2 else "denied", status=200, scopes=["x"])
    head = log.head()
    assert head[0] == 4
    assert log.verify(public_key=key.public_multikey, expected_head=head) == []

    db = sqlite3.connect(path)
    raw = json.loads(db.execute("SELECT entry FROM audit_log WHERE seq=2").fetchone()[0])
    raw["body"]["outcome"] = "allowed"
    db.execute("UPDATE audit_log SET entry=? WHERE seq=2", (json.dumps(raw),))
    db.commit()
    problems = AuditLog(path).verify(public_key=key.public_multikey)
    assert any("entry 2" in p for p in problems)


def test_audit_truncation_detected_against_exported_head(tmp_path):
    path = str(tmp_path / "a.db")
    log = AuditLog(path)
    for i in range(3):
        log.record(agent="did:agent:a", outcome="allowed", status=200)
    head = log.head()
    db = sqlite3.connect(path)
    db.execute("DELETE FROM audit_log WHERE seq=2")
    db.commit()
    assert AuditLog(path).verify() == []  # a prefix is internally consistent...
    assert AuditLog(path).verify(expected_head=head)  # ...but the exported head is gone


def test_audit_unsigned_entry_rejected_when_key_required(tmp_path):
    log = AuditLog(str(tmp_path / "a.db"))
    log.record(agent="did:agent:a", outcome="allowed", status=200)
    assert log.verify(public_key=KeyPair.generate().public_multikey)


def test_fastapi_authorizer_writes_audit(w):
    audit = AuditLog()
    keys = w["keys"]
    require = fastapi_authorizer(RequestVerifier(keys, audiences={SVC}),
                                 GrantVerifier(keys, trust_principals({w["human"].did: ["pay.*"]})), audit=audit)
    app = FastAPI()

    async def price(r):
        return (await r.json())["cents"]

    @app.post("/buy")
    def buy(who=Depends(require("pay.buy", amount=price, unit="USD-cents"))):
        return {"ok": True}

    c = TestClient(app, base_url=f"http://{SVC}")
    g = w["human"].grant(w["agent"].did, ["pay.buy"], [SVC], limits=Limits.build(total=100))
    assert c.post("/buy", json={"cents": 60}, auth=w["agent"].httpx_auth(g)).status_code == 200
    assert c.post("/buy", json={"cents": 60}, auth=w["agent"].httpx_auth(g)).status_code == 402
    entries = [e["body"] for e in audit.entries()]
    assert [(e["outcome"], e["status"], e["amount"], e["charged"]) for e in entries] == \
        [("allowed", 200, 60, 60), ("denied", 402, 60, 0)]
    assert entries[0]["principal"] == w["human"].did and entries[0]["grants"] == [[w["human"].did, g.leaf.id]]
    with pytest.raises(ValueError):
        audit.record(agent="x", outcome="maybe", status=200)


def test_real_mcp_client_signs_its_requests():
    """The official MCP client, given AgentSigAuth as its HTTP auth, talks to a protected MCP server."""
    pytest.importorskip("mcp.client.streamable_http")
    import anyio
    import httpx2
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    from mcp.server.mcpserver import MCPServer

    human, _ = AgentIdentity.create(name="h")
    agent, _ = AgentIdentity.create(name="a")
    table = {i.did: (i.current_key.public_multikey, i.kid) for i in (human, agent)}
    server = MCPServer("demo")

    @server.tool()
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b

    @server.tool()
    def wipe() -> str:
        """Dangerous."""
        return "wiped"

    inner = server.streamable_http_app(stateless_http=True, json_response=True)
    aud = "127.0.0.1:8000"
    app = AgentAuthMiddleware(inner, verifier=RequestVerifier(table.get, audiences={aud}),
                              grants=GrantVerifier(table.get, trust_principals({human.did: ["mcp.*"]})),
                              rules=mcp_rules())
    grant = human.grant(agent.did, ["mcp.session", "mcp.tools.add"], [aud])
    seen = {}

    async def main():
        async with inner.router.lifespan_context(inner):
            client = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), auth=agent.httpx_auth(grant))
            async with streamable_http_client(f"http://{aud}/mcp", http_client=client) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    seen["add"] = (await session.call_tool("add", {"a": 2, "b": 40})).structured_content
                    try:
                        await session.call_tool("wipe", {})
                    except Exception as e:  # the 403 surfaces as a transport error
                        seen["wipe"] = type(e).__name__

    anyio.run(main)
    assert seen["add"] == {"result": 42}
    assert "wipe" in seen

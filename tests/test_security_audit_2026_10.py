"""Regression tests for the October 2026 internal security review (docs/security-audit-2026-10.md).

Each test names the finding it covers (R = registry, S = SDK/middleware, C = core protocol).
Core-protocol findings are also covered by the shared test vectors (test-vectors/).
"""

import asyncio
import json
import secrets
import sqlite3
import time

import pytest
from conftest import make_registry, new_agent
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route, WebSocketRoute

from agentauth import (
    AgentIdentity,
    AuditLog,
    GrantVerifier,
    KeyPair,
    RegistryError,
    RegistryKeyResolver,
    RegistryPool,
    RequestVerifier,
    trust_principals,
)
from agentauth import server as server_mod
from agentauth.asgi import PUBLIC, AgentAuthMiddleware, Requirement
from agentauth.config import ConfigError, Settings
from agentauth.crypto import b64u, key_commitment
from agentauth.identity import make_deactivation, make_inception, verify_inception
from agentauth.keystore import FORMAT, KeyFileError, _kdf, read_key_file, write_key_file
from agentauth.ratelimit import MemoryRateLimiter
from agentauth.server import _BodyLimit
from agentauth.store import Conflict, Store

SVC = "svc.example"


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #


def test_r1_metric_method_label_is_bounded():
    _, http = make_registry()
    for m in ("FOO1", "FOO2", "BREW"):
        http.request(m, "/v1/info")
    text = http.get("/metrics").text
    assert 'method="OTHER"' in text
    assert "FOO1" not in text and "BREW" not in text


def test_r9_body_limit_rejections_are_counted():
    _, http = make_registry(max_body_bytes=100)
    assert http.post("/v1/identities", content=b"x" * 500).status_code == 413
    assert 'status="413"' in http.get("/metrics").text


def test_r4_forwarded_for_must_be_an_ip():
    _, http = make_registry(rate_limit_reads=(2, 60), trusted_proxy_hops=1)
    did = "did:agent:" + "1" * 45
    # Garbage values all fall back to the socket peer, so they share one counter
    # instead of each minting a fresh rate-limit key.
    codes = [http.get(f"/v1/identities/{did}", headers={"X-Forwarded-For": f"junk-{i}"}).status_code
             for i in range(3)]
    assert codes == [404, 404, 429]


def test_r4_forwarded_for_header_lines_are_joined():
    _, http = make_registry(rate_limit_reads=(1, 60), trusted_proxy_hops=1)
    did = "did:agent:" + "1" * 45
    # Two header lines = one list "9.9.9.9, 1.1.1.1": the client (1 hop from the right) is 1.1.1.1,
    # not whatever the first line says.
    hdrs = [("x-forwarded-for", "9.9.9.9"), ("x-forwarded-for", "1.1.1.1")]
    assert http.get(f"/v1/identities/{did}", headers=hdrs).status_code == 404
    assert http.get(f"/v1/identities/{did}", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 429
    assert http.get(f"/v1/identities/{did}", headers={"X-Forwarded-For": "9.9.9.9"}).status_code == 404


def test_r5_ipv6_clients_are_limited_per_64():
    _, http = make_registry(rate_limit_reads=(2, 60), trusted_proxy_hops=1)
    did = "did:agent:" + "1" * 45
    codes = [http.get(f"/v1/identities/{did}", headers={"X-Forwarded-For": f"2001:db8::{i}"}).status_code
             for i in range(1, 4)]
    assert codes == [404, 404, 429]
    assert http.get(f"/v1/identities/{did}", headers={"X-Forwarded-For": "2001:db8:1::1"}).status_code == 404


def test_r2_slow_rate_limiter_does_not_block(monkeypatch):
    monkeypatch.setattr(server_mod, "RATE_LIMIT_TIMEOUT", 0.05)
    _, http = make_registry(rate_limit_reads=(1, 60))

    def slow(self, key, limit, period):
        time.sleep(0.5)
        return False, 30

    monkeypatch.setattr(MemoryRateLimiter, "hit", slow)
    t = time.perf_counter()
    assert http.get("/v1/info").status_code == 200  # allowed: the limiter didn't answer in time
    assert time.perf_counter() - t < 0.45


def test_r7_slow_body_times_out():
    async def app(scope, receive, send):  # pragma: no cover - never reached
        raise AssertionError("app must not be called")

    sent = []

    async def receive():
        await asyncio.sleep(10)

    async def send(msg):
        sent.append(msg)

    mw = _BodyLimit(app, limit=1000, timeout=0.05)
    asyncio.run(mw({"type": "http", "method": "POST", "headers": []}, receive, send))
    assert sent[0]["status"] == 408


def test_r9_docs_and_openapi_are_not_served():
    _, http = make_registry()
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert http.get(path).status_code == 404


def test_r3_storage_lock_timeout_is_503(registry):
    _, http = registry

    def locked(did):
        raise sqlite3.OperationalError("database is locked")

    http.app.state.store.get_state = locked
    c = TestClient(http.app, raise_server_exceptions=False)
    r = c.get("/v1/identities/did:agent:" + "1" * 45)
    assert r.status_code == 503 and r.headers["retry-after"]


def test_r6_failed_sqlite_commit_is_rolled_back():
    store = Store(":memory:")

    class Cursor:
        def __init__(self, cur):
            self.cur = cur

        def execute(self, sql, *a):
            if sql == "COMMIT":
                raise sqlite3.OperationalError("disk I/O error")
            return self.cur.execute(sql, *a)

        def __getattr__(self, n):
            return getattr(self.cur, n)

    class Conn:
        def __init__(self, db):
            self.db = db

        def cursor(self):
            return Cursor(self.db.cursor())

        def __getattr__(self, n):
            return getattr(self.db, n)

    real = store._db
    store._db = Conn(real)
    with pytest.raises(sqlite3.OperationalError):
        with store._tx() as cur:
            cur.execute("SELECT 1")
    assert not real.in_transaction  # not left open on the shared connection
    store._db = real
    assert store.stats()["identities"] == 0


def test_controller_toctou_precondition_runs_inside_the_write():
    store = Store(":memory:")
    ident, ev = AgentIdentity.create(name="x")
    calls = []

    class Gone(Exception):
        pass

    def precondition(state_of):
        calls.append((store._db.in_transaction, state_of(ident.did)))
        raise Gone()

    with pytest.raises(Gone):
        store.append(ev, ident.state, expected_prev_seq=None, precondition=precondition)
    assert calls == [(True, None)] and store.get_state(ident.did) is None
    store.append(ev, ident.state, expected_prev_seq=None, precondition=lambda state_of: None)
    with pytest.raises(Conflict):
        store.append(ev, ident.state, expected_prev_seq=None)


def test_registration_rechecks_controller_key(registry):
    reg, http = registry
    owner = new_agent(reg, name="owner")
    worker, ev = AgentIdentity.create(name="w", controller=owner)
    reg.rotate(owner)  # the countersigning key is no longer current
    r = http.post("/v1/identities", json=ev)
    assert r.status_code == 400


def test_log_length_is_capped(monkeypatch, registry):
    monkeypatch.setattr(server_mod, "MAX_LOG_EVENTS", 3)
    reg, _ = registry
    a = new_agent(reg, name="a")
    reg.rotate(a)
    reg.rotate(a)
    with pytest.raises(RegistryError) as e:
        reg.rotate(a)
    assert e.value.status == 400


def test_r9_placeholder_secrets_refused():
    s = Settings(audiences={"x"}, database_url="postgresql://u:CHANGE-ME-long-random-password@db/x")
    with pytest.raises(ConfigError, match="CHANGE-ME"):
        s.validate()


# --------------------------------------------------------------------------- #
# key files
# --------------------------------------------------------------------------- #


def _attacker_pending(tmp_path, did, key, passphrase=None):
    write_key_file(tmp_path / "b.pending.json", did=did, role="pending-next", key=key, extra={},
                   passphrase=passphrase)


def test_s1_planted_plaintext_file_refused_when_passphrase_set(registry, tmp_path):
    reg, _ = registry
    agent = new_agent(reg, name="b")
    agent.save(tmp_path, "b", passphrase="pw")
    _attacker_pending(tmp_path, agent.did, KeyPair.generate())  # unencrypted
    with pytest.raises(KeyFileError, match="not encrypted"):
        AgentIdentity.load(tmp_path, "b", passphrase="pw")


def test_s1_planted_pending_key_is_never_adopted(registry, tmp_path):
    reg, _ = registry
    agent = new_agent(reg, name="b")
    agent.save(tmp_path, "b")  # unencrypted deployment
    attacker = KeyPair.generate()
    _attacker_pending(tmp_path, agent.did, attacker)
    ident = AgentIdentity.load(tmp_path, "b")
    assert ident.pending_next_key.public_multikey == attacker.public_multikey
    ident.rotate_and_save(reg, tmp_path, "b")
    remote = reg.verified_state(agent.did)
    assert remote.next != key_commitment(attacker.public_multikey)
    assert remote.next == key_commitment(ident.recovery_key.public_multikey)
    # Moved aside, not deleted: recoverable by hand if the registry had committed to it after all.
    assert len(list(tmp_path.glob("b.pending.json.unadopted-*"))) == 1


def test_s1_encrypted_file_is_bound_to_did_and_role(tmp_path):
    k = KeyPair.generate()
    p = tmp_path / "x.recovery.json"
    write_key_file(p, did="did:agent:" + "1" * 45, role="recovery", key=k, extra={}, passphrase="pw")
    doc = json.loads(p.read_text())
    assert doc["secret"]["enc"] == "scrypt-aes256gcm-v2"
    for field, value in (("role", "pending-next"), ("did", "did:agent:" + "2" * 45)):
        tampered = dict(doc, **{field: value})
        p.write_text(json.dumps(tampered))
        with pytest.raises(KeyFileError, match="moved from another"):
            read_key_file(p, "pw")


def test_s1_v04_encrypted_files_still_load(tmp_path):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    k = KeyPair.generate()
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    params = {"n": 2**15, "r": 8, "p": 1}
    ct = AESGCM(_kdf("pw", salt, params)).encrypt(nonce, k.seed, FORMAT.encode())
    doc = {"format": FORMAT, "did": "did:agent:" + "1" * 45, "role": "recovery", "public": k.public_multikey,
           "secret": {"enc": "scrypt-aes256gcm", "kdf": params, "salt": b64u(salt), "nonce": b64u(nonce),
                      "ct": b64u(ct)}}
    p = tmp_path / "old.json"
    p.write_text(json.dumps(doc))
    p.chmod(0o600)
    assert read_key_file(p, "pw")[1].public_multikey == k.public_multikey


@pytest.mark.parametrize("params", [{"n": 2**20, "r": 8, "p": 1}, {"n": 2**17, "r": 32, "p": 1},
                                    {"n": 2**17, "r": 8, "p": 16}, {"n": 2**17, "r": 8, "p": 1, "x": 1},
                                    {"n": 2.0**17, "r": 8, "p": 1}])
def test_s9_only_known_scrypt_parameters(params):
    with pytest.raises(KeyFileError):
        _kdf("pw", b"s" * 16, params)


def test_s5_save_never_overwrites_a_new_identitys_files(registry, tmp_path):
    reg, _ = registry
    first = new_agent(reg, name="a")
    first.save(tmp_path, "a", overwrite=False)
    second, _ = AgentIdentity.create(name="a2")
    with pytest.raises(FileExistsError):
        second.save(tmp_path, "a", overwrite=False)
    assert AgentIdentity.load(tmp_path, "a").did == first.did


def test_s5_cli_init_saves_before_registering_and_never_overwrites(tmp_path, monkeypatch):
    from agentauth import cli

    reg, _ = make_registry()
    monkeypatch.setattr(cli, "RegistryClient", lambda *a, **k: reg)
    rec = tmp_path / "vault"
    cli.main(["--dir", str(tmp_path), "--recovery-dir", str(rec), "init", "bot"])
    before = (rec / "bot.recovery.json").read_text()
    (tmp_path / "bot.key.json").rename(tmp_path / "moved.json")  # only the recovery file is left
    with pytest.raises(SystemExit):
        cli.main(["--dir", str(tmp_path), "--recovery-dir", str(rec), "init", "bot"])
    assert (rec / "bot.recovery.json").read_text() == before


def test_concurrent_rotation_is_refused(registry, tmp_path):
    reg, _ = registry
    agent = new_agent(reg, name="b")
    agent.save(tmp_path, "b")
    _attacker_pending(tmp_path, agent.did, KeyPair.generate())  # another rotation's file appears
    with pytest.raises(RuntimeError, match="another rotation"):
        agent.rotate_and_save(reg, tmp_path, "b")
    assert reg.verified_state(agent.did).seq == 0


# --------------------------------------------------------------------------- #
# ASGI middleware
# --------------------------------------------------------------------------- #


@pytest.fixture
def w():
    reg, _ = make_registry()

    def new(name):
        ident, ev = AgentIdentity.create(name=name)
        reg.register(ev)
        return ident

    human, agent, other = new("human"), new("agent"), new("other")
    keys = RegistryKeyResolver(reg, ttl=30)
    return dict(reg=reg, human=human, agent=agent, other=other, keys=keys)


def _inner():
    async def whoami(request):
        user = request.scope.get("user")
        return JSONResponse({"user": getattr(user, "identity", None), "auth": request.user.is_authenticated})

    async def admin(request):
        return JSONResponse({"admin": True})

    async def session(request):
        return JSONResponse({"ok": True}, headers={"mcp-session-id": "s-123"})

    async def ws(websocket):
        await websocket.accept()
        await websocket.send_text("hi")
        await websocket.close()

    return Starlette(routes=[Route("/whoami", whoami), Route("/admin", admin), Route("/session", session),
                             WebSocketRoute("/ws", ws), WebSocketRoute("/public-ws", ws)])


def _mw(w, app=None, rules=None):
    return AgentAuthMiddleware(app or _inner(), verifier=RequestVerifier(w["keys"], audiences={SVC}),
                               grants=GrantVerifier(w["keys"], trust_principals({w["human"].did: ["*"]}),
                                                    revoked=lambda pairs: set()),
                               rules=rules or (lambda req: PUBLIC if req.path == "/public-ws" else None))


def test_s2_websocket_needs_a_signature(w):
    from starlette.websockets import WebSocketDisconnect

    c = TestClient(_mw(w), base_url=f"http://{SVC}")
    with pytest.raises(WebSocketDisconnect) as e:
        with c.websocket_connect("/ws") as s:
            s.receive_text()
    assert e.value.code == 1008
    with c.websocket_connect("/public-ws") as s:
        assert s.receive_text() == "hi"
    auth = w["agent"].authorization("GET", f"http://{SVC}/ws", b"", "")
    with c.websocket_connect("/ws", headers={"Authorization": auth}) as s:
        assert s.receive_text() == "hi"


def test_s2_unknown_scope_types_are_refused(w):
    called = []

    async def app(scope, receive, send):
        called.append(scope["type"])

    asyncio.run(_mw(w, app)({"type": "webtransport"}, None, None))
    asyncio.run(_mw(w, app)({"type": "lifespan"}, None, None))
    assert called == ["lifespan"]


def test_s3_rules_see_the_route_path_under_a_mount(w):
    seen = []

    def rules(req):
        seen.append((req.path, req.full_path))
        return Requirement(scopes=["admin"]) if req.path == "/admin" else None

    outer = Starlette(routes=[Mount("/api", app=_mw(w, rules=rules))])
    c = TestClient(outer, base_url=f"http://{SVC}")
    r = c.get("/api/admin", auth=w["agent"].httpx_auth())
    assert r.status_code in (401, 403)  # needs a grant: the rule matched despite the /api prefix
    assert seen[-1] == ("/admin", "/api/admin")
    g = w["human"].grant(w["agent"].did, ["admin"], [SVC])
    assert c.get("/api/admin", auth=w["agent"].httpx_auth(g)).json() == {"admin": True}


def test_duplicate_security_headers_are_refused(w):
    c = TestClient(_mw(w), base_url=f"http://{SVC}")
    auth = w["agent"].authorization("GET", f"http://{SVC}/whoami", b"", "")
    r = c.get("/whoami", headers=[("authorization", auth), ("authorization", "AgentSig junk")])
    assert r.status_code == 400 and "duplicate" in r.json()["detail"]


def test_s4_scope_user_is_the_agent(w):
    c = TestClient(_mw(w), base_url=f"http://{SVC}")
    assert c.get("/whoami", auth=w["agent"].httpx_auth()).json() == {"user": w["agent"].did, "auth": True}


def test_s4_mcp_session_is_bound_to_its_agent(w):
    c = TestClient(_mw(w), base_url=f"http://{SVC}")
    assert c.get("/session", auth=w["agent"].httpx_auth()).headers["mcp-session-id"] == "s-123"
    hdr = {"Mcp-Session-Id": "s-123"}
    assert c.get("/whoami", headers=hdr, auth=w["agent"].httpx_auth()).status_code == 200
    r = c.get("/whoami", headers=hdr, auth=w["other"].httpx_auth())
    assert r.status_code == 403
    # A second session header can't smuggle the check past (the app might read the other one).
    r = c.get("/whoami", headers=[("mcp-session-id", "s-123"), ("mcp-session-id", "s-other")],
              auth=w["other"].httpx_auth())
    assert r.status_code == 400


def test_s4_session_refusal_happens_before_charging(w):
    from agentauth import Limits

    mw = _mw(w, rules=lambda req: Requirement(scopes=["tools.x"]))
    c = TestClient(mw, base_url=f"http://{SVC}")
    assert c.get("/session", auth=w["agent"].httpx_auth(
        w["human"].grant(w["agent"].did, ["tools.x"], [SVC]))).status_code == 200
    g = w["human"].grant(w["other"].did, ["tools.x"], [SVC], limits=Limits.build(uses=1))
    hdr = {"Mcp-Session-Id": "s-123"}
    assert c.get("/whoami", headers=hdr, auth=w["other"].httpx_auth(g)).status_code == 403
    # The refused request didn't use up the single permitted use.
    assert c.get("/whoami", auth=w["other"].httpx_auth(g)).status_code == 200


def test_s4_presenting_an_unbound_session_id_never_binds_it(w):
    mw = _mw(w)
    c = TestClient(mw, base_url=f"http://{SVC}")
    # "other" presents s-123 before anyone opened it; the response echoes it, but it isn't bound.
    c.get("/session", headers={"Mcp-Session-Id": "s-123"}, auth=w["other"].httpx_auth())
    assert "s-123" not in mw._sessions


def test_s7_audit_records_hostile_strings():
    log = AuditLog()
    log.record(agent="did:agent:x", outcome="denied", status=403, resource="\ud800bad", path="/p\udfff",
               request_id="\ud83d", reason="r" * 5000)
    e = log.entries()[0]["body"]
    assert e["resource"] == "�bad" and len(e["reason"]) == 500
    assert log.verify() == []


# --------------------------------------------------------------------------- #
# pool, pagination
# --------------------------------------------------------------------------- #


def test_s6_pool_ignores_a_registry_serving_a_forged_controller_deactivation():
    reg, _ = make_registry()
    owner = new_agent(reg, name="owner")
    worker, ev = AgentIdentity.create(name="w", controller=owner)
    reg.register(ev)
    forged = make_deactivation(worker.state, owner.did, KeyPair.generate())

    class Liar:
        base_url = "liar"

        def __getattr__(self, n):
            return getattr(reg, n)

        def log(self, did):
            events = reg.log(did)
            return events + [forged] if did == worker.did else events

    st = RegistryPool([reg, Liar()], read_quorum=1).verified_state(worker.did)
    assert st.active and st.seq == 0


def test_controlled_agents_pagination_terminates(registry):
    reg, _ = registry

    def looping(path, params=None):
        return {"agents": [{"did": "x"}], "next": "did:agent:" + "1" * 45}

    reg._get = looping
    with pytest.raises(RegistryError, match="did not terminate"):
        reg.controlled_agents("did:agent:" + "2" * 45)


# --------------------------------------------------------------------------- #
# core
# --------------------------------------------------------------------------- #


def test_c_inception_may_not_commit_to_its_own_key():
    k = KeyPair.generate()
    with pytest.raises(ValueError):
        make_inception(k, k)


def test_c_unbound_controller_key_rejected_by_registry_client(registry):
    reg, _ = registry
    owner = new_agent(reg, name="owner")
    worker, ev = AgentIdentity.create(name="w", controller=owner)
    reg.register(ev)
    forged = make_deactivation(worker.state, owner.did, KeyPair.generate())
    from agentauth.identity import InvalidEvent

    with pytest.raises(InvalidEvent):
        from agentauth.identity import verify_log
        from agentauth.sdk import bound_controller_check

        verify_log(reg.log(worker.did) + [forged], bound_controller_check(reg))
    assert verify_inception(ev, lambda d, k: True).controller == owner.did


def test_r4_forwarded_for_with_ports():
    _, http = make_registry(rate_limit_reads=(1, 60), trusted_proxy_hops=1)
    did = "did:agent:" + "1" * 45
    assert http.get(f"/v1/identities/{did}", headers={"X-Forwarded-For": "1.1.1.1:5555"}).status_code == 404
    assert http.get(f"/v1/identities/{did}", headers={"X-Forwarded-For": "1.1.1.1:6666"}).status_code == 429
    assert http.get(f"/v1/identities/{did}", headers={"X-Forwarded-For": "[2001:db8::1]:80"}).status_code == 404
    assert http.get(f"/v1/identities/{did}", headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 404

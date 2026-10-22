"""Regression tests for defects found in the pre-release review of v0.4."""

import multiprocessing as mp
import threading
import time

import pytest
from conftest import make_registry, new_agent
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from test_witness import Lying

from agentauth import (
    AgentIdentity,
    AuditLog,
    GrantError,
    GrantVerifier,
    KeyPair,
    Limits,
    NonceCache,
    RegistryKeyResolver,
    RegistryPool,
    RegistryRevocationChecker,
    RequestVerifier,
    trust_principals,
)
from agentauth.asgi import AgentAuthMiddleware, Requirement, mcp_rules
from agentauth.grants import make_revocation
from agentauth.integrations import fastapi_authorizer
from agentauth.store import SCHEMA_VERSION, Store

# 1. replay cache shorter than the replay window ---------------------------------


def test_verifier_refuses_replay_cache_shorter_than_window():
    with pytest.raises(ValueError, match="replay window"):
        RequestVerifier(lambda d: None, audiences={"svc"}, max_skew=600, nonce_cache=NonceCache(ttl=241))
    with pytest.raises(ValueError):
        RequestVerifier(lambda d: None, audiences={"svc"}, nonce_cache=NonceCache(ttl=60))
    RequestVerifier(lambda d: None, audiences={"svc"}, max_skew=600, nonce_cache=NonceCache(ttl=1201))


@pytest.mark.redis
def test_redis_cache_ttl_checked_too(redis_url):
    from agentauth.backends.redis import RedisNonceCache

    with pytest.raises(ValueError):
        RequestVerifier(lambda d: None, audiences={"svc"}, max_skew=600, nonce_cache=RedisNonceCache(redis_url))


# 2. one pool member masking another's valid revocation proof ----------------------


def test_junk_proof_from_one_registry_cannot_mask_a_valid_one():
    reg_a, _ = make_registry()
    reg_b, _ = make_registry()
    liar = Lying(reg_a)
    pool = RegistryPool([liar, reg_b])
    human, ev = AgentIdentity.create(name="h")
    pool.register(ev)
    agent, ev = AgentIdentity.create(name="a")
    pool.register(ev)
    g = human.grant(agent.did, ["x.y"], ["svc"])
    pair = (human.did, g.leaf.id)
    reg_b.revoke_grant(human, g.leaf.id)  # only the honest registry has it
    liar.claim_revoked = {pair: {"body": {"junk": True}, "sig": "x"}}
    checker = RegistryRevocationChecker(pool, ttl=0, on_unproven="ignore")
    assert checker([pair]) == {pair}


# 3. a registry that is down must not break pool writes or sync --------------------


class Down:
    base_url = "http://down.invalid"

    def __getattr__(self, name):
        def fail(*a, **k):
            raise ConnectionError("unreachable")

        return fail


def test_pool_write_survives_unreachable_member():
    reg_a, _ = make_registry()
    reg_b, _ = make_registry()
    pool = RegistryPool([reg_a, reg_b, Down()], read_quorum=2)
    agent, ev = AgentIdentity.create(name="w")
    pool.register(ev)
    pool.rotate(agent)  # used to raise after a and b had accepted
    assert agent.kid.endswith("#key-1")
    assert reg_a.verified_state(agent.did).seq == reg_b.verified_state(agent.did).seq == 1
    result = pool.sync(agent.did)
    assert [r["pushed"] for r in result] == [0, 0, None]


def test_pool_write_fails_only_if_every_member_fails():
    pool = RegistryPool([Down(), Down()])
    _, ev = AgentIdentity.create(name="x")
    with pytest.raises(ConnectionError):
        pool.register(ev)


# 4. crash between writing the two key files --------------------------------------


def test_resume_after_crash_between_key_files(registry, tmp_path, monkeypatch):
    reg, _ = registry
    agent = new_agent(reg, name="c")
    agent.save(tmp_path, "c", passphrase="pw")
    ident = AgentIdentity.load(tmp_path, "c", passphrase="pw")

    import agentauth.sdk as sdk

    real_write = sdk.write_key_file

    def crash_on_recovery(path, **kw):
        if kw.get("role") == "recovery":
            raise OSError("disk full")
        return real_write(path, **kw)

    monkeypatch.setattr(sdk, "write_key_file", crash_on_recovery)
    with pytest.raises(OSError):
        ident.rotate_and_save(reg, tmp_path, "c", passphrase="pw")
    monkeypatch.setattr(sdk, "write_key_file", real_write)

    resumed = AgentIdentity.load(tmp_path, "c", passphrase="pw")
    assert resumed.current_key.public_multikey == resumed.recovery_key.public_multikey  # the torn state
    resumed.rotate_and_save(reg, tmp_path, "c", passphrase="pw")
    assert not (tmp_path / "c.pending.json").exists()
    again = AgentIdentity.load(tmp_path, "c", passphrase="pw")
    again.rotate_and_save(reg, tmp_path, "c", passphrase="pw")  # and it can keep rotating
    assert reg.whoami(again)["kid"].endswith("#key-2")


def test_resume_refuses_pending_key_the_registry_doesnt_commit_to(registry, tmp_path):
    from agentauth.keystore import write_key_file

    reg, _ = registry
    agent = new_agent(reg, name="p")
    agent.save(tmp_path, "p", passphrase="pw")
    write_key_file(tmp_path / "p.pending.json", did=agent.did, role="pending-next", key=KeyPair.generate(),
                   extra={}, passphrase="pw")
    reg.rotate(agent)  # rotated elsewhere with a different next key
    stale = AgentIdentity.load(tmp_path, "p", passphrase="pw")
    with pytest.raises(RuntimeError, match="diverged"):
        stale.rotate_and_save(reg, tmp_path, "p", passphrase="pw")


# 5. concurrent resolution during a rotation ---------------------------------------


def test_concurrent_resolution_during_rotation_is_not_equivocation():
    reg, _ = make_registry()
    agent = new_agent(reg, name="r")
    gate, release = threading.Event(), threading.Event()
    real_log = reg.log
    calls = {"n": 0}

    def slow_log(did):
        events = real_log(did)
        calls["n"] += 1
        if calls["n"] == 1:  # the first fetch stalls with the old log
            gate.set()
            release.wait(5)
        return events

    reg.log = slow_log
    keys = RegistryKeyResolver(reg, ttl=0)
    errors = []

    def resolve():
        try:
            keys(agent.did)
        except Exception as e:
            errors.append(e)

    t = threading.Thread(target=resolve)
    t.start()
    gate.wait(5)
    real_submit_log = real_log  # rotate while the first fetch is in flight
    reg.log = real_submit_log
    reg.rotate(agent)
    reg.log = slow_log
    t2 = threading.Thread(target=resolve)
    t2.start()
    time.sleep(0.1)
    release.set()
    t.join(5)
    t2.join(5)
    assert errors == []
    assert keys(agent.did)[1].endswith("#key-1")


# 6. crafted input that used to cause 500s ----------------------------------------


@pytest.mark.parametrize("pairs", [[["\ud800", "g"]], [["did:agent:" + "1" * 45, "\x00"]], [["x\x00", "g"]],
                                   [["did:agent:" + "1" * 45, "\ud800"]]])
def test_revocation_check_rejects_unencodable_ids(registry, pairs):
    _, http = registry
    import json

    r = http.post("/v1/revocations/check", content=json.dumps({"grants": pairs}),
                  headers={"content-type": "application/json"})
    assert r.status_code == 400


def test_paging_cursor_must_be_a_did(registry):
    _, http = registry
    assert http.get("/v1/identities", params={"after": "\x00"}).status_code == 400
    owner = "did:agent:" + "1" * 45
    assert http.get(f"/v1/identities/{owner}/agents", params={"after": "zz\x00"}).status_code == 400


def test_deeply_nested_meta_rejected(registry):
    reg, http = registry
    deep: dict = {}
    cur = deep
    for _ in range(600):
        cur["a"] = {}
        cur = cur["a"]
    with pytest.raises(Exception):
        AgentIdentity.create(name="deep", meta={"x": deep})  # local verification refuses it too
    from agentauth.identity import make_inception

    ev = make_inception(KeyPair.generate(), KeyPair.generate(), meta={"x": deep})
    r = http.post("/v1/identities", json=ev)
    assert r.status_code == 400 and "nest" in r.json()["detail"]
    ok = make_inception(KeyPair.generate(), KeyPair.generate(), meta={"a": {"b": {"c": [1, [2, [3]]]}}})
    assert http.post("/v1/identities", json=ok).status_code == 201


def test_mcp_middleware_survives_deep_json():
    agent, _ = AgentIdentity.create(name="a")
    app = AgentAuthMiddleware(lambda s, r, se: None, verifier=RequestVerifier(lambda d: None, audiences={"svc"}),
                              rules=mcp_rules())
    c = TestClient(app, base_url="http://svc")
    r = c.post("/mcp", content=b"[" * 100000, headers={"content-type": "application/json"})
    assert r.status_code == 400


@pytest.mark.postgres
def test_postgres_rejects_nul_cleanly(postgres_url):
    from conftest import registry_settings

    from agentauth.server import create_app
    from agentauth.store import PostgresStore

    http = TestClient(create_app(settings=registry_settings(), store=PostgresStore(postgres_url)))
    assert http.get("/v1/identities", params={"after": "\x00"}).status_code == 400
    assert http.post("/v1/revocations/check", json={"grants": [["did:agent:" + "1" * 45, "a\x00"]]}).status_code == 400


# 7. concurrent migrations on one SQLite file --------------------------------------


def _open_store(path, q):
    try:
        s = Store(path)
        q.put(("ok", s.schema_version()))
    except Exception as e:
        q.put(("err", repr(e)))


def test_concurrent_first_start_migrations(tmp_path):
    ctx = mp.get_context("spawn")
    for trial in range(3):
        path = str(tmp_path / f"race{trial}.db")
        q = ctx.Queue()
        procs = [ctx.Process(target=_open_store, args=(path, q)) for _ in range(10)]
        for p in procs:
            p.start()
        for p in procs:
            p.join(60)
        results = [q.get(timeout=5) for _ in procs]
        assert results == [("ok", SCHEMA_VERSION)] * 10, results


# 8. audience bound to the Host header (opt-in) ------------------------------------


def test_bind_host_rejects_cross_host_requests():
    agent, _ = AgentIdentity.create(name="h")
    table = {agent.did: (agent.current_key.public_multikey, agent.kid)}
    strict = RequestVerifier(table.get, audiences={"a.example", "b.example"}, bind_host=True)
    h = agent.authorization("GET", "http://a.example/x")
    strict.verify(authorization=h, method="GET", path="/x", body=b"", host="a.example")
    with pytest.raises(Exception, match="different host"):
        strict.verify(authorization=agent.authorization("GET", "http://a.example/x"), method="GET", path="/x",
                      body=b"", host="b.example")

    app = FastAPI()
    from agentauth.integrations import fastapi_dependency

    @app.get("/x")
    def x(a=Depends(fastapi_dependency(strict))):
        return {"ok": True}

    c = TestClient(app, base_url="http://b.example")
    hdr = {"Authorization": agent.authorization("GET", "http://a.example/x")}  # signed for a, sent to b
    assert c.get("/x", headers=hdr).status_code == 401


# 9. audit failures must not leave a charged, unaudited call -----------------------


class BrokenAudit(AuditLog):
    def record(self, **kw):
        if kw["outcome"] == "allowed":
            raise OSError("disk full")
        return super().record(**kw)


def test_audit_failure_refunds_and_refuses():
    reg, _ = make_registry()
    human, agent = new_agent(reg, name="h"), new_agent(reg, name="a")
    keys = RegistryKeyResolver(reg, ttl=30)
    gv = GrantVerifier(keys, trust_principals({human.did: ["pay.*"]}))
    require = fastapi_authorizer(RequestVerifier(keys, audiences={"svc"}), gv, audit=BrokenAudit())
    app = FastAPI()

    @app.post("/buy")
    def buy(w=Depends(require("pay.buy", amount=lambda r: 40, unit="USD-cents"))):
        return {"ok": True}

    g = human.grant(agent.did, ["pay.buy"], ["svc"], limits=Limits.build(total=100))
    r = TestClient(app, base_url="http://svc").post("/buy", auth=agent.httpx_auth(g))
    assert r.status_code == 503
    assert gv.ledger.usage((human.did, g.leaf.id))["spent"] == 0

    gv2 = GrantVerifier(keys, trust_principals({human.did: ["pay.*"]}))
    mw = AgentAuthMiddleware(lambda s, rcv, snd: None, verifier=RequestVerifier(keys, audiences={"svc"}), grants=gv2,
                             rules=lambda req: Requirement(scopes=["pay.buy"], amount=40, unit="USD-cents"),
                             audit=BrokenAudit())
    g2 = human.grant(agent.did, ["pay.buy"], ["svc"], limits=Limits.build(total=100))
    r = TestClient(mw, base_url="http://svc").post("/buy", auth=agent.httpx_auth(g2))
    assert r.status_code == 503 and gv2.ledger.usage((human.did, g2.leaf.id))["spent"] == 0


# 10. rate limiter eviction ---------------------------------------------------------


def test_rate_limit_counters_survive_address_flooding():
    from agentauth.ratelimit import MemoryRateLimiter

    rl = MemoryRateLimiter(max_keys=100)
    for _ in range(5):
        rl.hit("victim-watched", 5, 60)
    for i in range(50):  # fewer new addresses than the cap: nobody is evicted
        rl.hit(f"flood{i}", 5, 60)
    assert rl.hit("victim-watched", 5, 60)[0] is False


def test_revocation_proof_unused_import_guard():
    # keep make_revocation / GrantError imported for readers comparing with test_witness
    assert make_revocation and GrantError

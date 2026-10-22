"""Redis replay cache and usage ledger: same semantics as the in-memory versions, shared across replicas."""

import pytest
from conftest import make_registry
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from agentauth import (
    AgentIdentity,
    GrantVerifier,
    LimitError,
    Limits,
    RegistryKeyResolver,
    RequestVerifier,
    trust_principals,
)
from agentauth.integrations import fastapi_authorizer

pytestmark = pytest.mark.redis


@pytest.fixture
def backends(redis_url):
    from agentauth.backends.redis import RedisNonceCache, RedisUsageLedger

    return RedisNonceCache(redis_url, ttl=5), RedisUsageLedger(redis_url)


def test_nonce(backends):
    nonces, _ = backends
    assert nonces.check_and_store("d", "n1") is True
    assert nonces.check_and_store("d", "n1") is False
    assert nonces.check_and_store("other", "n1") is True
    assert 0 < nonces.r.ttl("agentauth:nonce:d:n1") <= 5


def test_all_or_nothing(backends):
    _, led = backends
    parent, child = (("i", "p"), Limits.build(total=100)), (("i", "c"), Limits.build(total=100))
    led.consume([parent], 90)
    with pytest.raises(LimitError) as e:
        led.consume([parent, child], 20)
    assert e.value.status == 402 and "10" in str(e.value)
    assert led.usage(("i", "c"))["spent"] == 0


def test_uses_and_rate(backends):
    _, led = backends
    uses = (("i", "u"), Limits.build(uses=2))
    led.consume([uses], 0)
    led.consume([uses], 0)
    with pytest.raises(LimitError) as e:
        led.consume([uses], 0)
    assert e.value.status == 403
    rate = (("i", "r"), Limits.build(rate=(2, 60)))
    led.consume([rate], 0, now=1000)
    led.consume([rate], 0, now=1010)
    with pytest.raises(LimitError) as e:
        led.consume([rate], 0, now=1020)
    assert e.value.status == 429 and "retry in 40s" in str(e.value)
    led.consume([rate], 0, now=1061)


def test_refund_and_expiry(backends):
    _, led = backends
    import time

    link = (("i", "g"), Limits.build(total=100))
    led.consume([link], 60, expires_at={("i", "g"): time.time() + 120})
    led.refund([link], 100)  # clamps at zero
    assert led.usage(("i", "g"))["spent"] == 0
    assert 60 < led.r.ttl("agentauth:ledger:i:g:spent") <= 181  # follows the grant's expiry


def _service(reg, keys, human, nonces, ledger):
    require = fastapi_authorizer(
        RequestVerifier(keys, audiences={"svc.example"}, nonce_cache=nonces),
        GrantVerifier(keys, trust_principals({human.did: ["pay.*"]}), ledger=ledger),
    )
    app = FastAPI()

    async def price(r):
        return (await r.json())["cents"]

    @app.post("/buy")
    def buy(who=Depends(require("pay.buy", amount=price, unit="USD-cents"))):
        return {"ok": True}

    return TestClient(app, base_url="http://svc.example")


def test_two_replicas_share_budget_and_replay_protection(redis_url):
    """Two independent service instances (separate verifiers, caches, connections) behind one Redis."""
    from agentauth.backends.redis import RedisNonceCache, RedisUsageLedger

    reg, _ = make_registry()
    human, ev = AgentIdentity.create(name="h")
    reg.register(ev)
    agent, ev = AgentIdentity.create(name="a")
    reg.register(ev)
    replicas = [
        _service(reg, RegistryKeyResolver(reg, ttl=30), human, RedisNonceCache(redis_url), RedisUsageLedger(redis_url))
        for _ in range(2)
    ]
    g = human.grant(agent.did, ["pay.buy"], ["svc.example"], limits=Limits.build(total=100))
    body = b'{"cents": 40}'
    headers = {**agent.headers("POST", "http://svc.example/buy", body, g), "content-type": "application/json"}
    assert replicas[0].post("/buy", content=body, headers=headers).status_code == 200
    r = replicas[1].post("/buy", content=body, headers=headers)  # same signed request, other replica
    assert r.status_code == 401 and "replayed" in r.json()["detail"]

    def buy(i):
        return replicas[i % 2].post("/buy", json={"cents": 40}, auth=agent.httpx_auth(g)).status_code

    assert [buy(i) for i in range(3)] == [200, 402, 402]  # 40 + 40 = 80; a third 40 would exceed 100


def test_redis_down_fails_closed():
    from agentauth.backends.redis import RedisNonceCache, RedisUsageLedger

    reg, _ = make_registry()
    human, ev = AgentIdentity.create(name="h")
    reg.register(ev)
    agent, ev = AgentIdentity.create(name="a")
    reg.register(ev)
    dead = "redis://127.0.0.1:1/0"
    client = _service(reg, RegistryKeyResolver(reg, ttl=30), human, RedisNonceCache(dead), RedisUsageLedger(dead))
    g = human.grant(agent.did, ["pay.buy"], ["svc.example"], limits=Limits.build(total=100))
    r = client.post("/buy", json={"cents": 1}, auth=agent.httpx_auth(g))
    assert r.status_code == 503


def test_registry_uses_redis_for_replay_protection(redis_url):
    """Two registry replicas sharing Redis reject a /whoami replayed across them."""
    reg_a, http_a = make_registry(redis_url=redis_url)
    agent, ev = AgentIdentity.create(name="w")
    reg_a.register(ev)
    # second replica over the same database is simulated by sharing the store object
    from conftest import registry_settings

    from agentauth.server import create_app

    app_b = create_app(settings=registry_settings(redis_url=redis_url), store=http_a.app.state.store)
    http_b = TestClient(app_b)
    h = {"Authorization": agent.authorization("GET", "http://testserver/v1/whoami")}
    assert http_a.get("/v1/whoami", headers=h).status_code == 200
    assert http_b.get("/v1/whoami", headers=h).status_code == 401
    assert http_b.get("/readyz").json()["checks"]["redis"] == "ok"

"""Races: budgets, replay caches and log appends under concurrent load.

The in-memory implementations are checked with threads. The Redis-backed ones
are checked with separate *processes* (what replicas actually are), each with
its own verifier and connection.
"""

import multiprocessing as mp
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from conftest import make_registry
from fastapi.testclient import TestClient

from agentauth import AgentIdentity, GrantError, GrantVerifier, LimitError, Limits, NonceCache, UsageLedger
from agentauth.identity import make_rotation
from agentauth.store import Conflict, Store


def _race(n, fn):
    barrier = threading.Barrier(n)

    def run(i):
        barrier.wait()
        return fn(i)

    with ThreadPoolExecutor(n) as ex:
        return list(ex.map(run, range(n)))


def test_ledger_budget_never_overspent_under_threads():
    led = UsageLedger()
    parent = (("i", "parent"), Limits.build(total=1000))
    children = [(("i", f"c{i}"), Limits.build(total=1000)) for i in range(8)]

    def spend(i):
        ok = 0
        for _ in range(50):
            try:
                led.consume([parent, children[i % 8]], 7)
                ok += 1
            except LimitError:
                pass
        return ok

    accepted = sum(_race(16, spend))
    assert accepted == 1000 // 7
    assert led.usage(parent[0])["spent"] == accepted * 7 <= 1000


def test_uses_counter_exact_under_threads():
    led = UsageLedger()
    link = (("i", "g"), Limits.build(uses=100))

    def call(i):
        try:
            led.consume([link], 0)
            return 1
        except LimitError:
            return 0

    assert sum(_race(64, lambda i: sum(call(i) for _ in range(5)))) == 100


def test_nonce_accepted_exactly_once_under_threads():
    c = NonceCache(ttl=60)
    assert sum(_race(32, lambda i: c.check_and_store("did", "same-nonce"))) == 1


def test_concurrent_appends_one_winner(tmp_path):
    store = Store(str(tmp_path / "s.db"))
    ident, ev = AgentIdentity.create(name="race")
    store.append(ev, ident.state, None)
    from agentauth.identity import apply_event

    events = [make_rotation(ident.state, ident.recovery_key, AgentIdentity.create()[0].current_key) for _ in range(16)]

    def append(i):
        try:
            store.append(events[i], apply_event(ident.state, events[i], lambda d, k: True), 0)
            return "ok"
        except Conflict:
            return "conflict"

    results = _race(16, append)
    assert results.count("ok") == 1 and results.count("conflict") == 15
    assert len(store.get_log(ident.did)) == 2 and store.verify_integrity() == []


def test_concurrent_registry_submissions_one_winner(tmp_path):
    reg, http = make_registry(str(tmp_path / "r.db"))
    ident, ev = AgentIdentity.create(name="race")
    reg.register(ev)
    events = [make_rotation(ident.state, ident.recovery_key, AgentIdentity.create()[0].current_key) for _ in range(12)]
    client = TestClient(http.app)
    codes = _race(12, lambda i: client.post(f"/v1/identities/{ident.did}/events", json=events[i]).status_code)
    assert codes.count(200) == 1 and set(codes) <= {200, 400, 409}
    assert len(reg.log(ident.did)) == 2


def test_concurrent_registration_of_same_identity(tmp_path):
    reg, http = make_registry(str(tmp_path / "r.db"))
    _, ev = AgentIdentity.create(name="dup")
    client = TestClient(http.app)
    codes = _race(12, lambda i: client.post("/v1/identities", json=ev).status_code)
    assert codes.count(201) == 1 and codes.count(409) == 11


def test_grant_budget_under_threads_through_verifier():
    """End to end through GrantVerifier.enforce: concurrent callers sharing a parent budget."""
    reg, _ = make_registry()
    from agentauth import RegistryKeyResolver, trust_principals

    def new(name):
        ident, ev = AgentIdentity.create(name=name)
        reg.register(ev)
        return ident

    human, agent = new("h"), new("a")
    subs = [new(f"s{i}") for i in range(4)]
    gv = GrantVerifier(RegistryKeyResolver(reg, ttl=300), trust_principals({human.did: ["pay.*"]}))
    root = human.grant(agent.did, ["pay.*"], ["svc"], depth=1, limits=Limits.build(total=500))
    chains = [agent.grant(s.did, ["pay.buy"], ["svc"], parent=root, limits=Limits.build(total=400)) for s in subs]
    authz = [gv.verify(c.encode(), requester=s.did, audience="svc") for c, s in zip(chains, subs)]

    def buy(i):
        ok = 0
        for _ in range(40):
            try:
                gv.enforce(authz[i % 4], amount=3, unit="USD-cents")
                ok += 1
            except GrantError as e:
                assert e.status == 402
        return ok

    total = sum(_race(8, buy))
    assert total * 3 <= 500 and total == 500 // 3


# --------------------------------------------------------------------------- #
# across processes, through Redis
# --------------------------------------------------------------------------- #


def _redis_spender(url, n, out):
    from agentauth.backends.redis import RedisUsageLedger

    led = RedisUsageLedger(url)
    parent = (("i", "parent"), Limits.build(total=1000, uses=400))
    child = (("i", f"child-{mp.current_process().pid}"), Limits.build(total=1000))
    ok = 0
    for _ in range(n):
        try:
            led.consume([parent, child], 7)
            ok += 1
        except LimitError:
            pass
    out.put(ok)


@pytest.mark.redis
def test_redis_ledger_shared_by_processes(redis_url):
    ctx = mp.get_context("spawn")
    out = ctx.Queue()
    procs = [ctx.Process(target=_redis_spender, args=(redis_url, 60, out)) for _ in range(6)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
    accepted = sum(out.get(timeout=5) for _ in procs)
    from agentauth.backends.redis import RedisUsageLedger

    spent = RedisUsageLedger(redis_url).usage(("i", "parent"))["spent"]
    assert accepted == 1000 // 7 and spent == accepted * 7


def _redis_nonce(url, out, start):
    from agentauth.backends.redis import RedisNonceCache

    c = RedisNonceCache(url, ttl=60)
    while time.time() < start:
        pass
    out.put(sum(c.check_and_store("did:agent:x", f"nonce-{i:04d}") for i in range(200)))


@pytest.mark.redis
def test_redis_nonce_accepted_once_across_processes(redis_url):
    ctx = mp.get_context("spawn")
    out = ctx.Queue()
    start = time.time() + 2
    procs = [ctx.Process(target=_redis_nonce, args=(redis_url, out, start)) for _ in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
    assert sum(out.get(timeout=5) for _ in procs) == 200  # each nonce won by exactly one process

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from agentauth import (
    AgentIdentity,
    AuthorizedAgent,
    GrantChain,
    GrantError,
    GrantVerifier,
    Limits,
    LimitError,
    RegistryClient,
    RegistryKeyResolver,
    RequestVerifier,
    UsageLedger,
    trust_principals,
)
from agentauth.crypto import canonical_json
from agentauth.grants import Grant
from agentauth.integrations import fastapi_authorizer
from agentauth.limits import pattern_covers, pattern_matches
from agentauth.server import create_app

SVC = "svc.example"


@pytest.fixture
def world(tmp_path):
    reg = RegistryClient("http://testserver", client=TestClient(
        create_app(db_path=str(tmp_path / "r.db"), audiences={"testserver"})))

    def new(name):
        ident, ev = AgentIdentity.create(name=name)
        reg.register(ev)
        return ident

    human, agent, sub_a, sub_b = new("human"), new("agent"), new("sub_a"), new("sub_b")
    keys = RegistryKeyResolver(reg, ttl=0)
    grants = GrantVerifier(keys, trust_principals({human.did: ["tools.*", "files.*", "payments.*"]}))
    require = fastapi_authorizer(RequestVerifier(keys, audiences={SVC}), grants)

    async def price(r):
        return (await r.json())["amount_cents"]

    app = FastAPI()

    @app.get("/files")
    def read_file(path: str, who: AuthorizedAgent = Depends(require("files.read", resource=lambda r: r.query_params["path"]))):
        return {"path": path}

    @app.post("/buy")
    def buy(body: dict, who: AuthorizedAgent = Depends(require("payments.buy", amount=price, unit="USD-cents"))):
        if body.get("fail"):
            who.refund()
            return {"ok": False, "refunded": body["amount_cents"]}
        return {"ok": True, "charged": who.charged}

    @app.post("/buy-eur")
    def buy_eur(body: dict, who=Depends(require("payments.buy", amount=price, unit="EUR-cents"))):
        return {"ok": True}

    @app.post("/search")
    def search(who=Depends(require("tools.search"))):
        return {"ok": True}

    client = TestClient(app, base_url=f"http://{SVC}")
    return dict(reg=reg, human=human, agent=agent, a=sub_a, b=sub_b, client=client, ledger=grants.ledger)


def get_file(w, who, chain, path):
    return w["client"].get("/files", params={"path": path}, auth=who.httpx_auth(chain))


def buy(w, who, chain, cents, fail=False, path="/buy"):
    return w["client"].post(path, json={"amount_cents": cents, "fail": fail}, auth=who.httpx_auth(chain))


# --------------------------------------------------------------------------- #
# pure logic
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("p,r,ok", [
    ("/reports/*", "/reports/q3.pdf", True),
    ("/reports/*", "/reports/2026/q3.pdf", True),
    ("/reports/*", "/reportsX", False),
    ("/reports/q3.pdf", "/reports/q3.pdf", True),
    ("/reports/q3.pdf", "/reports/q4.pdf", False),
])
def test_pattern_matches(p, r, ok):
    assert pattern_matches(p, r) is ok


@pytest.mark.parametrize("parent,child,ok", [
    ("/reports/*", "/reports/2026/*", True),
    ("/reports/*", "/reports/q3.pdf", True),
    ("/reports/2026/*", "/reports/*", False),
    ("/reports/q3.pdf", "/reports/*", False),
])
def test_pattern_covers(parent, child, ok):
    assert pattern_covers(parent, child) is ok


def test_rate_narrowing_compares_rates_not_counts():
    parent = Limits.build(rate=(10, 60))           # 1 call / 6 s
    assert parent.narrowing_violation(Limits.build(rate=(5, 60))) is None
    assert parent.narrowing_violation(Limits.build(rate=(100, 3600))) is None   # 1 / 36 s
    assert "rate" in parent.narrowing_violation(Limits.build(rate=(5, 10)))     # 1 / 2 s


def test_unknown_limits_fail_closed():
    with pytest.raises(LimitError, match="unknown"):
        Limits.from_dict({"resources": ["/a/*"], "geo_fence": "EU"})


def test_rate_window_slides():
    led, key = UsageLedger(), ("iss", "g1")
    lim = Limits.build(rate=(2, 60))
    led.consume([(key, lim)], 0, now=1000)
    led.consume([(key, lim)], 0, now=1010)
    with pytest.raises(LimitError) as e:
        led.consume([(key, lim)], 0, now=1020)
    assert e.value.status == 429
    led.consume([(key, lim)], 0, now=1061)  # first call has left the window


def test_ledger_is_all_or_nothing():
    led = UsageLedger()
    parent, child = (("i", "p"), Limits.build(total=100)), (("i", "c"), Limits.build(total=100))
    led.consume([parent], 90)
    with pytest.raises(LimitError):
        led.consume([parent, child], 20)
    assert led.usage(("i", "c"))["spent"] == 0  # child was not charged either


# --------------------------------------------------------------------------- #
# resources
# --------------------------------------------------------------------------- #


def test_resource_limits(world):
    w = world
    g = w["human"].grant(w["agent"].did, ["files.read"], [SVC], limits=Limits.build(resources=["/reports/*"]))
    assert get_file(w, w["agent"], g, "/reports/q3.pdf").status_code == 200
    r = get_file(w, w["agent"], g, "/secrets/keys.txt")
    assert r.status_code == 403 and "resource" in r.json()["detail"]
    r = get_file(w, w["agent"], g, "/reports/../secrets/keys.txt")
    assert r.status_code == 400 and ".." in r.json()["detail"]


def test_resource_limited_grant_fails_closed_on_undeclared_endpoint(world):
    w = world
    g = w["human"].grant(w["agent"].did, ["tools.*"], [SVC], limits=Limits.build(resources=["repo:acme/*"]))
    r = w["client"].post("/search", auth=w["agent"].httpx_auth(g))
    assert r.status_code == 403 and "names none" in r.json()["detail"]


def test_delegation_narrows_resources(world):
    w = world
    root = w["human"].grant(w["agent"].did, ["files.*"], [SVC], depth=1, limits=Limits.build(resources=["/reports/*"]))
    child = w["agent"].grant(w["a"].did, ["files.read"], [SVC], parent=root,
                             limits=Limits.build(resources=["/reports/2026/*"]))
    assert get_file(w, w["a"], child, "/reports/2026/q3.pdf").status_code == 200
    assert get_file(w, w["a"], child, "/reports/2025/q3.pdf").status_code == 403
    with pytest.raises(GrantError, match="outside"):
        w["agent"].grant(w["a"].did, ["files.read"], [SVC], parent=root, limits=Limits.build(resources=["/secrets/*"]))


def test_child_inherits_parent_limits(world):
    w = world
    root = w["human"].grant(w["agent"].did, ["files.*"], [SVC], depth=1, limits=Limits.build(resources=["/reports/*"]))
    child = w["agent"].grant(w["a"].did, ["files.read"], [SVC], parent=root)  # no limits given
    assert child.leaf.body["limits"] == {"resources": ["/reports/*"]}
    assert get_file(w, w["a"], child, "/secrets/x").status_code == 403


def test_hand_forged_loosening_rejected(world):
    """A delegating agent that skips the SDK and drops its parent's limits is caught by the service."""
    w = world
    root = w["human"].grant(w["agent"].did, ["files.*"], [SVC], depth=1, limits=Limits.build(resources=["/reports/*"]))
    body = {
        "v": "agentauth-grant/1", "id": "forged-id-000000000000", "iss": w["agent"].did, "kid": w["agent"].kid,
        "sub": w["a"].did, "scope": ["files.read"], "aud": [SVC],
        "nbf": root.leaf.nbf, "exp": root.leaf.exp, "depth": 0, "parent": root.leaf.id,
    }  # note: no "limits"
    forged = GrantChain(root.links + [Grant(body, w["agent"].current_key.sign(canonical_json(body)))])
    r = get_file(w, w["a"], forged, "/secrets/x")
    assert r.status_code == 403 and "loosens" in r.json()["detail"]


# --------------------------------------------------------------------------- #
# spend
# --------------------------------------------------------------------------- #


def test_per_call_limit(world):
    w = world
    g = w["human"].grant(w["agent"].did, ["payments.buy"], [SVC], limits=Limits.build(per_call=5000))
    assert buy(w, w["agent"], g, 4999).status_code == 200
    r = buy(w, w["agent"], g, 5001)
    assert r.status_code == 403 and "per-call" in r.json()["detail"]


def test_budget_is_shared_across_delegations(world):
    """Two sub-agents each get ≤ the parent's budget, but together can't exceed it."""
    w = world
    root = w["human"].grant(w["agent"].did, ["payments.*"], [SVC], depth=1, limits=Limits.build(total=1000))
    ca = w["agent"].grant(w["a"].did, ["payments.buy"], [SVC], parent=root, limits=Limits.build(total=800))
    cb = w["agent"].grant(w["b"].did, ["payments.buy"], [SVC], parent=root, limits=Limits.build(total=800))
    assert buy(w, w["a"], ca, 700).status_code == 200
    r = buy(w, w["b"], cb, 400)
    assert r.status_code == 402 and "300" in r.json()["detail"]
    assert buy(w, w["b"], cb, 300).status_code == 200
    assert w["ledger"].usage((w["human"].did, root.leaf.id))["spent"] == 1000


def test_delegation_cannot_raise_budget(world):
    w = world
    root = w["human"].grant(w["agent"].did, ["payments.*"], [SVC], depth=1, limits=Limits.build(total=1000))
    with pytest.raises(GrantError, match="total"):
        w["agent"].grant(w["a"].did, ["payments.buy"], [SVC], parent=root, limits=Limits.build(total=5000))


def test_refund(world):
    w = world
    g = w["human"].grant(w["agent"].did, ["payments.buy"], [SVC], limits=Limits.build(total=1000))
    r = buy(w, w["agent"], g, 900, fail=True)
    assert r.json() == {"ok": False, "refunded": 900}
    assert buy(w, w["agent"], g, 1000).status_code == 200


def test_unit_mismatch(world):
    w = world
    g = w["human"].grant(w["agent"].did, ["payments.buy"], [SVC], limits=Limits.build(total=1000))
    r = buy(w, w["agent"], g, 10, path="/buy-eur")
    assert r.status_code == 403 and "EUR" in r.json()["detail"]


# --------------------------------------------------------------------------- #
# rate & uses
# --------------------------------------------------------------------------- #


def test_rate_limit(world):
    w = world
    g = w["human"].grant(w["agent"].did, ["tools.search"], [SVC], limits=Limits.build(rate=(2, 60)))
    call = lambda: w["client"].post("/search", auth=w["agent"].httpx_auth(g))
    assert call().status_code == 200 and call().status_code == 200
    r = call()
    assert r.status_code == 429 and "retry" in r.json()["detail"]


def test_use_count(world):
    w = world
    g = w["human"].grant(w["agent"].did, ["tools.search"], [SVC], limits=Limits.build(uses=3))
    codes = [w["client"].post("/search", auth=w["agent"].httpx_auth(g)).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 403]


def test_parent_rate_applies_to_all_children(world):
    w = world
    root = w["human"].grant(w["agent"].did, ["tools.*"], [SVC], depth=1, limits=Limits.build(rate=(3, 60)))
    ca = w["agent"].grant(w["a"].did, ["tools.search"], [SVC], parent=root)
    cb = w["agent"].grant(w["b"].did, ["tools.search"], [SVC], parent=root)
    codes = [w["client"].post("/search", auth=who.httpx_auth(c)).status_code
             for who, c in [(w["a"], ca), (w["b"], cb), (w["a"], ca), (w["b"], cb)]]
    assert codes == [200, 200, 200, 429]

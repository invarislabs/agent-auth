"""A dishonest registry: withholding, rollback, forks, and false revocation claims."""

import pytest
from conftest import make_registry, new_agent
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from agentauth import (
    AgentIdentity,
    EquivocationError,
    GrantVerifier,
    KelPins,
    KeyPair,
    RegistryError,
    RegistryKeyResolver,
    RegistryPool,
    RegistryRevocationChecker,
    RequestVerifier,
    SQLitePins,
    trust_principals,
)
from agentauth.grants import make_revocation
from agentauth.identity import make_rotation
from agentauth.integrations import fastapi_dependency


class Lying:
    """Wraps a RegistryClient and lets a test tamper with what it serves."""

    def __init__(self, inner):
        self.inner = inner
        self.base_url = inner.base_url
        self.truncate_to = None
        self.claim_revoked: dict = {}
        self.hide_revocations = False

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def log(self, did):
        events = self.inner.log(did)
        return events[: self.truncate_to] if self.truncate_to else events

    def verified_state(self, did):
        from agentauth.identity import verify_log

        return verify_log(self.log(did))

    def revocation_proofs(self, pairs):
        out = {} if self.hide_revocations else self.inner.revocation_proofs(pairs)
        out.update({p: v for p, v in self.claim_revoked.items() if p in pairs})
        return out

    def revoked(self, pairs):
        return set(self.revocation_proofs(pairs))


# --------------------------------------------------------------------------- #
# pins
# --------------------------------------------------------------------------- #


def test_rollback_hiding_a_deactivation_is_detected():
    reg, _ = make_registry()
    owner = new_agent(reg, name="owner")
    agent = new_agent(reg, name="agent", controller=owner)
    liar = Lying(reg)
    keys = RegistryKeyResolver(liar, ttl=0)
    assert keys(agent.did) is not None

    reg.deactivate_controlled(owner, agent.did)
    assert keys(agent.did) is None  # honest answer, now pinned at seq 1

    liar.truncate_to = 1  # registry now pretends the deactivation never happened
    with pytest.raises(EquivocationError, match="rolled back"):
        keys(agent.did)


def test_rollback_makes_service_fail_closed():
    reg, _ = make_registry()
    agent = new_agent(reg, name="a")
    reg.rotate(agent)
    liar = Lying(reg)
    keys = RegistryKeyResolver(liar, ttl=0)
    app = FastAPI()
    dep = fastapi_dependency(RequestVerifier(keys, audiences={"svc.example"}))

    @app.get("/x")
    def x(a=Depends(dep)):
        return {"ok": True}

    c = TestClient(app, base_url="http://svc.example")
    assert c.get("/x", auth=agent.httpx_auth()).status_code == 200
    liar.truncate_to = 1
    r = c.get("/x", auth=agent.httpx_auth())
    assert r.status_code == 503 and "rolled back" in r.json()["detail"]


def test_forgotten_identity_is_equivocation():
    reg, _ = make_registry()
    agent = new_agent(reg, name="a")
    keys = RegistryKeyResolver(reg, ttl=0)
    keys(agent.did)

    def gone(did):
        raise RegistryError(404, "unknown identity")

    reg.log = gone
    with pytest.raises(EquivocationError):
        keys(agent.did)


def _fork(reg_a, reg_b, agent):
    """The recovery-key holder signs two different rotations; each registry gets one."""
    ev1 = make_rotation(agent.state, agent.recovery_key, KeyPair.generate())
    ev2 = make_rotation(agent.state, agent.recovery_key, KeyPair.generate())
    reg_a.submit(agent.did, ev1)
    reg_b.submit(agent.did, ev2)


def test_fork_seen_over_time_is_detected(tmp_path):
    reg_a, _ = make_registry()
    reg_b, _ = make_registry()
    agent, inc = AgentIdentity.create(name="forky")
    reg_a.register(inc)
    reg_b.register(inc)
    _fork(reg_a, reg_b, agent)

    pins = SQLitePins(str(tmp_path / "pins.db"))
    RegistryKeyResolver(reg_a, ttl=0, pins=pins)(agent.did)
    # A restarted service (new resolver, same pin file) that now talks to the other registry notices.
    with pytest.raises(EquivocationError, match="conflicting"):
        RegistryKeyResolver(reg_b, ttl=0, pins=SQLitePins(str(tmp_path / "pins.db")))(agent.did)


def test_pins_unit():
    reg, _ = make_registry()
    agent = new_agent(reg, name="p")
    reg.rotate(agent)
    log = reg.log(agent.did)
    pins = KelPins()
    pins.check_and_update(agent.did, log[:1])
    pins.check_and_update(agent.did, log)  # extension is fine
    pins.check_and_update(agent.did, log)  # so is the same log again
    with pytest.raises(EquivocationError):
        pins.check_and_update(agent.did, log[:1])


# --------------------------------------------------------------------------- #
# registry pool
# --------------------------------------------------------------------------- #


def test_pool_withholding_needs_every_registry():
    reg_a, _ = make_registry()
    reg_b, _ = make_registry()
    liar = Lying(reg_b)
    pool = RegistryPool([reg_a, liar])
    owner, ev = AgentIdentity.create(name="owner")
    pool.register(ev)
    agent, ev = AgentIdentity.create(name="agent", controller=owner)
    pool.register(ev)
    pool.deactivate_controlled(owner, agent.did)
    assert reg_b.verified_state(agent.did).active is False  # write reached both

    liar.truncate_to = 1  # one registry hides the deactivation...
    keys = RegistryKeyResolver(pool, ttl=0)
    assert keys(agent.did) is None  # ...but the pool still sees it


def test_pool_detects_fork_between_registries():
    reg_a, _ = make_registry()
    reg_b, _ = make_registry()
    agent, inc = AgentIdentity.create(name="f")
    reg_a.register(inc)
    reg_b.register(inc)
    _fork(reg_a, reg_b, agent)
    with pytest.raises(EquivocationError):
        RegistryKeyResolver(RegistryPool([reg_a, reg_b]), ttl=0)(agent.did)


def test_pool_sync_backfills_lagging_registry():
    reg_a, _ = make_registry()
    reg_b, _ = make_registry()
    agent = new_agent(reg_a, name="lag")
    reg_a.rotate(agent)
    reg_a.rotate(agent)
    pool = RegistryPool([reg_a, reg_b])
    assert [r["pushed"] for r in pool.sync(agent.did)] == [0, 3]
    assert len(reg_b.log(agent.did)) == 3
    assert pool.verified_state(agent.did).seq == 2


def test_pool_read_quorum():
    reg_a, _ = make_registry()
    reg_b, _ = make_registry()
    agent = new_agent(reg_a, name="q")
    pool = RegistryPool([reg_a, reg_b], read_quorum=2)

    def down(did):
        raise ConnectionError("down")

    reg_b.log = down
    with pytest.raises(RuntimeError, match="only 1 of 2"):
        pool.log(agent.did)
    assert RegistryPool([reg_a, reg_b], read_quorum=1).verified_state(agent.did).did == agent.did


def test_pool_rotation_reaches_all():
    reg_a, _ = make_registry()
    reg_b, _ = make_registry()
    pool = RegistryPool([reg_a, reg_b])
    agent, ev = AgentIdentity.create(name="r")
    pool.register(ev)
    pool.rotate(agent)
    assert reg_a.verified_state(agent.did).seq == reg_b.verified_state(agent.did).seq == 1
    assert pool.whoami(agent)["kid"].endswith("#key-1")
    assert [i["software"] for i in pool.info()] == ["agentauth-registry"] * 2


# --------------------------------------------------------------------------- #
# revocation proofs
# --------------------------------------------------------------------------- #


@pytest.fixture
def rv():
    reg, _ = make_registry()
    human, agent = new_agent(reg, name="h"), new_agent(reg, name="a")
    return reg, human, agent


def test_genuine_revocation_has_verifiable_proof(rv):
    reg, human, agent = rv
    g = human.grant(agent.did, ["tools.x"], ["svc"])
    reg.revoke_grant(human, g.leaf.id)
    proofs = reg.revocation_proofs([(human.did, g.leaf.id)])
    assert proofs[(human.did, g.leaf.id)]["body"]["grant"] == g.leaf.id
    checker = RegistryRevocationChecker(reg, ttl=0, on_unproven="ignore")
    assert checker([(human.did, g.leaf.id)]) == {(human.did, g.leaf.id)}
    assert checker.unproven_claims == 0


def test_false_revocation_claim_without_proof(rv):
    reg, human, agent = rv
    g = human.grant(agent.did, ["tools.x"], ["svc"])
    pair = (human.did, g.leaf.id)
    liar = Lying(reg)
    liar.claim_revoked = {pair: None}
    # Default: fail closed (deny), but count it.
    deny = RegistryRevocationChecker(liar, ttl=0)
    assert deny([pair]) == {pair} and deny.unproven_claims == 1
    # Availability-first deployments only honour verified proofs.
    assert RegistryRevocationChecker(liar, ttl=0, on_unproven="ignore")([pair]) == set()


def test_forged_proof_rejected(rv):
    reg, human, agent = rv
    g = human.grant(agent.did, ["tools.x"], ["svc"])
    pair = (human.did, g.leaf.id)
    forged = make_revocation(issuer_did=human.did, issuer_key=KeyPair.generate(), grant_id=g.leaf.id)
    wrong_grant = make_revocation(issuer_did=human.did, issuer_key=human.current_key, grant_id="other-grant")
    for proof in (forged, wrong_grant, {"body": {}, "sig": ""}, "nonsense"):
        liar = Lying(reg)
        liar.claim_revoked = {pair: proof}
        assert RegistryRevocationChecker(liar, ttl=0, on_unproven="ignore")([pair]) == set()


def test_proof_signed_before_issuer_rotation_still_verifies(rv):
    reg, human, agent = rv
    g = human.grant(agent.did, ["tools.x"], ["svc"])
    reg.revoke_grant(human, g.leaf.id)
    reg.rotate(human)
    checker = RegistryRevocationChecker(reg, ttl=0, on_unproven="ignore")
    assert checker([(human.did, g.leaf.id)]) == {(human.did, g.leaf.id)}


def test_pool_revocation_hidden_by_one_registry_still_seen():
    reg_a, _ = make_registry()
    reg_b, _ = make_registry()
    liar = Lying(reg_b)
    liar.hide_revocations = True
    pool = RegistryPool([reg_a, liar])
    human, ev = AgentIdentity.create(name="h")
    pool.register(ev)
    agent, ev = AgentIdentity.create(name="a")
    pool.register(ev)
    g = human.grant(agent.did, ["tools.x"], ["svc"])
    pool.revoke_grant(human, g.leaf.id)
    keys = RegistryKeyResolver(pool, ttl=0)
    gv = GrantVerifier(keys, trust_principals({human.did: ["tools.*"]}),
                       revoked=RegistryRevocationChecker(pool, ttl=0, on_unproven="ignore"))
    from agentauth import GrantError

    with pytest.raises(GrantError, match="revoked"):
        gv.verify(g.encode(), requester=agent.did, audience="svc")

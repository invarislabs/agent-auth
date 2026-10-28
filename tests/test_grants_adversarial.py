"""Attacks on grant chains, limits and the authorization path, and fail-closed behaviour."""

import copy

import pytest
from conftest import make_registry
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from agentauth import (
    AgentIdentity,
    GrantChain,
    GrantError,
    GrantVerifier,
    LimitError,
    Limits,
    RegistryKeyResolver,
    RequestVerifier,
    UsageLedger,
    trust_principals,
)
from agentauth.crypto import b64u, canonical_json
from agentauth.grants import MAX_HEADER_BYTES, Grant, make_revocation, verify_revocation
from agentauth.integrations import fastapi_authorizer

SVC = "svc.example"


@pytest.fixture
def w():
    reg, _ = make_registry()

    def new(name):
        ident, ev = AgentIdentity.create(name=name)
        reg.register(ev)
        return ident

    human, agent, sub = new("human"), new("agent"), new("sub")
    keys = RegistryKeyResolver(reg, ttl=0)
    gv = GrantVerifier(keys, trust_principals({human.did: ["tools.*", "payments.*"]}))
    return dict(reg=reg, human=human, agent=agent, sub=sub, keys=keys, gv=gv)


def resign(issuer, body):
    return Grant(body, issuer.current_key.sign(canonical_json(body)))


def test_unknown_grant_field_rejected(w):
    g = w["human"].grant(w["agent"].did, ["tools.search"], [SVC]).leaf
    body = dict(g.body, constraints={"geo": "EU"})  # a future field we don't understand
    with pytest.raises(GrantError, match="unknown fields"):
        w["gv"].verify(GrantChain([resign(w["human"], body)]).encode(), requester=w["agent"].did, audience=SVC)


@pytest.mark.parametrize("field,value", [
    ("aud", [5]), ("aud", ["has space"]), ("aud", []), ("scope", ["a b"]), ("scope", []),
    ("parent", 5), ("depth", -1), ("depth", True), ("nbf", 2**60), ("id", ""), ("id", "x" * 200),
    ("sub", "did:agent:x"), ("kid", "did:agent:someoneelse#key-0"), ("limits", []), ("limits", {"uses": 2**60}),
])
def test_bad_grant_fields_rejected(w, field, value):
    g = w["human"].grant(w["agent"].did, ["tools.search"], [SVC]).leaf
    body = dict(g.body)
    body[field] = value
    with pytest.raises(GrantError):
        w["gv"].verify(GrantChain([resign(w["human"], body)]).encode(), requester=w["agent"].did, audience=SVC)


def test_non_canonical_grant_signature_rejected(w):
    chain = w["human"].grant(w["agent"].did, ["tools.search"], [SVC])
    token = chain.encode()
    for bad in (token + "=", token.replace(".", ".=", 1)):
        with pytest.raises(GrantError):
            w["gv"].verify(bad, requester=w["agent"].did, audience=SVC)


def test_oversized_header_rejected(w):
    with pytest.raises(GrantError, match="larger"):
        w["gv"].verify("a" * (MAX_HEADER_BYTES + 1), requester=w["agent"].did, audience=SVC)


def test_self_issued_link_rejected(w):
    """An agent can't hand itself a fresh link (e.g. to reset a child budget) — iss == sub is refused."""
    root = w["human"].grant(w["agent"].did, ["tools.*"], [SVC], depth=2, limits=Limits.build(uses=1))
    body = {"v": "agentauth-grant/1", "id": "selfie-0000000000000", "iss": w["agent"].did, "kid": w["agent"].kid,
            "sub": w["agent"].did, "scope": ["tools.search"], "aud": [SVC], "nbf": root.leaf.nbf,
            "exp": root.leaf.exp, "depth": 0, "parent": root.leaf.id, "limits": {"uses": 1}}
    chain = GrantChain(root.links + [resign(w["agent"], body)])
    with pytest.raises(GrantError, match="own issuer"):
        w["gv"].verify(chain.encode(), requester=w["agent"].did, audience=SVC)


def test_duplicate_link_rejected(w):
    root = w["human"].grant(w["agent"].did, ["tools.*"], [SVC], depth=1)
    chain = GrantChain(root.links + root.links)
    with pytest.raises(GrantError):
        w["gv"].verify(chain.encode(), requester=w["agent"].did, audience=SVC)


def test_grant_for_other_audience_in_chain(w):
    root = w["human"].grant(w["agent"].did, ["tools.*"], [SVC, "other.example"], depth=1)
    child = w["agent"].grant(w["sub"].did, ["tools.search"], ["other.example"], parent=root)
    with pytest.raises(GrantError, match="audience"):
        w["gv"].verify(child.encode(), requester=w["sub"].did, audience=SVC)


def test_wildcard_scope_forms():
    from agentauth.grants import _valid_scope

    for ok in ("*", "a", "a.b", "a.*", "a.b.*"):
        assert _valid_scope(ok)
    for bad in ("", "a*", "*.a", "a.*.b", "a b", "**", "a.**", "x" * 200, 5, None):
        assert not _valid_scope(bad)


# --------------------------------------------------------------------------- #
# limits and the ledger
# --------------------------------------------------------------------------- #


def test_refund_cannot_mint_budget(w):
    g = w["human"].grant(w["agent"].did, ["payments.buy"], [SVC], limits=Limits.build(total=100))
    authz = w["gv"].verify(g.encode(), requester=w["agent"].did, audience=SVC)
    w["gv"].enforce(authz, amount=10, unit="USD-cents")
    for bad in (11, -5, 2.5, True):
        with pytest.raises(GrantError):
            authz.refund(bad)
    authz.refund(4)
    authz.refund()  # the remaining 6
    assert authz.charged == 0
    with pytest.raises(GrantError):
        authz.refund(1)
    assert w["gv"].ledger.usage((w["human"].did, g.leaf.id))["spent"] == 0


@pytest.mark.parametrize("amount", [-1, 1.5, True, "10", 2**60])
def test_bad_amounts_rejected(w, amount):
    g = w["human"].grant(w["agent"].did, ["payments.buy"], [SVC], limits=Limits.build(total=100))
    authz = w["gv"].verify(g.encode(), requester=w["agent"].did, audience=SVC)
    with pytest.raises(GrantError) as e:
        w["gv"].enforce(authz, amount=amount, unit="USD-cents")
    assert e.value.status == 400


def test_limit_values_bounded():
    for bad in ({"uses": 0}, {"uses": 2**53}, {"spend": {"unit": "a b", "total": 1}},
                {"spend": {"unit": "x" * 100, "total": 1}}, {"rate": {"count": 1, "per": 100000}},
                {"resources": ["a*b"]}, {"resources": []}, {"spend": {"unit": "u"}}):
        with pytest.raises(LimitError):
            Limits.from_dict(bad)


def test_multiple_enforce_calls_accumulate_charge(w):
    g = w["human"].grant(w["agent"].did, ["payments.buy"], [SVC], limits=Limits.build(total=100))
    authz = w["gv"].verify(g.encode(), requester=w["agent"].did, audience=SVC)
    w["gv"].enforce(authz, amount=30, unit="USD-cents")
    w["gv"].enforce(authz, amount=20, unit="USD-cents")
    assert authz.charged == 50
    authz.refund()
    assert w["gv"].ledger.usage((w["human"].did, g.leaf.id))["spent"] == 0


def test_ledger_prunes_expired_grants():
    led = UsageLedger(prune_every=10**9)
    lim = Limits.build(uses=5)
    led.consume([(("i", "old"), lim)], 0, expires_at={("i", "old"): 100})
    led.consume([(("i", "new"), lim)], 0, expires_at={("i", "new"): 10**12})
    assert len(led) == 2
    assert led.prune(now=200) == 1
    assert led.usage(("i", "old"))["uses"] == 0 and led.usage(("i", "new"))["uses"] == 1


def test_v03_style_ledger_still_supported(w):
    """A custom ledger written against v0.3 (no expires_at keyword) keeps working."""

    class OldLedger:
        def __init__(self):
            self.calls = []

        def consume(self, links, amount, now=None):
            self.calls.append((links, amount))

        def refund(self, links, amount):
            pass

    old = OldLedger()
    gv = GrantVerifier(w["keys"], trust_principals({w["human"].did: ["tools.*"]}), ledger=old)
    g = w["human"].grant(w["agent"].did, ["tools.search"], [SVC], limits=Limits.build(uses=3))
    gv.enforce(gv.verify(g.encode(), requester=w["agent"].did, audience=SVC))
    assert len(old.calls) == 1


# --------------------------------------------------------------------------- #
# fail closed when dependencies break
# --------------------------------------------------------------------------- #


def _svc(gv, keys):
    require = fastapi_authorizer(RequestVerifier(keys, audiences={SVC}), gv)
    app = FastAPI()

    @app.post("/do")
    def do(who=Depends(require("tools.search"))):
        return {"ok": True}

    return TestClient(app, base_url=f"http://{SVC}")


@pytest.mark.parametrize("broken", ["revocations", "root_policy", "ledger"])
def test_dependency_failures_return_503(w, broken):
    def boom(*a, **k):
        raise ConnectionError("backend down")

    class BoomLedger:
        consume = refund = staticmethod(boom)

    policy = trust_principals({w["human"].did: ["tools.*"]})
    gv = GrantVerifier(
        w["keys"],
        boom if broken == "root_policy" else policy,
        revoked=boom if broken == "revocations" else None,
        ledger=BoomLedger() if broken == "ledger" else None,
    )
    g = w["human"].grant(w["agent"].did, ["tools.search"], [SVC], limits=Limits.build(uses=5))
    r = _svc(gv, w["keys"]).post("/do", auth=w["agent"].httpx_auth(g))
    assert r.status_code == 503, r.text


def test_registry_outage_returns_503(w):
    gv = w["gv"]
    g = w["human"].grant(w["agent"].did, ["tools.search"], [SVC])
    client = _svc(gv, w["keys"])
    assert client.post("/do", auth=w["agent"].httpx_auth(g)).status_code == 200

    def down(did):
        raise ConnectionError("registry unreachable")

    w["reg"].log = down
    r = client.post("/do", auth=w["agent"].httpx_auth(g))
    assert r.status_code == 503


# --------------------------------------------------------------------------- #
# revocations
# --------------------------------------------------------------------------- #


def test_revocation_structure_is_strict(w):
    ev = make_revocation(issuer_did=w["human"].did, issuer_key=w["human"].current_key, grant_id="gid-1")
    verify_revocation(ev, w["human"].current_key.public_multikey)
    for mutate in (
        lambda e: e["body"].update(extra=1),
        lambda e: e["body"].update(ts=1.5),
        lambda e: e["body"].update(ts=True),
        lambda e: e["body"].update(grant=""),
        lambda e: e["body"].update(iss="nobody"),
        lambda e: e.update(sig=5),
        lambda e: e.update(extra=1),
    ):
        bad = copy.deepcopy(ev)
        mutate(bad)
        with pytest.raises(GrantError):
            verify_revocation(bad, w["human"].current_key.public_multikey)


def test_revocation_by_other_key_rejected_by_registry(w):
    ev = make_revocation(issuer_did=w["human"].did, issuer_key=w["agent"].current_key, grant_id="gid-1")
    from agentauth import RegistryError

    with pytest.raises(RegistryError) as e:
        w["reg"].submit_revocation(ev)
    assert e.value.status == 400


def test_revocation_signature_must_be_canonical(w):
    ev = make_revocation(issuer_did=w["human"].did, issuer_key=w["human"].current_key, grant_id="gid-1")
    ev["sig"] = ev["sig"] + "="
    with pytest.raises(GrantError):
        verify_revocation(ev, w["human"].current_key.public_multikey)
    assert b64u(b"x")  # keep import used


def test_new_grant_ids_never_start_with_dash(monkeypatch):
    """A leading '-' would make ids look like CLI options (this made CI flaky)."""
    import agentauth.grants as grants

    draws = iter(["-starts-with-dash-000", "-another-dash-000000", "fine-id-000000000000"])
    monkeypatch.setattr(grants.secrets, "token_urlsafe", lambda n: next(draws))
    assert grants.new_grant_id() == "fine-id-000000000000"
    monkeypatch.undo()
    assert not any(grants.new_grant_id().startswith("-") for _ in range(5000))

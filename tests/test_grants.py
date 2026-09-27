import copy
import time

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from agentauth import (
    AgentIdentity,
    AuthorizedAgent,
    GrantChain,
    GrantError,
    GrantVerifier,
    RegistryClient,
    RegistryKeyResolver,
    RegistryRevocationChecker,
    RequestVerifier,
    trust_principals,
)
from agentauth.crypto import canonical_json
from agentauth.grants import Grant, scope_covers
from agentauth.integrations import fastapi_authorizer
from agentauth.server import create_app

TOOLS = "tools.example"


@pytest.fixture
def world(tmp_path):
    """A registry, a human principal, her agent, a sub-agent, and a tool service that trusts her."""
    reg_app = create_app(db_path=str(tmp_path / "reg.db"), audiences={"testserver"})
    reg = RegistryClient("http://testserver", client=TestClient(reg_app))

    def new(name, controller=None):
        ident, ev = AgentIdentity.create(name=name, controller=controller)
        reg.register(ev)
        return ident

    human = new("arunima")
    agent = new("researcher", controller=human)
    sub = new("summarizer", controller=agent)
    stranger = new("stranger")

    # ttl=0: always resolve fresh, so deactivation/revocation take effect immediately in tests.
    keys = RegistryKeyResolver(reg, ttl=0)
    require = fastapi_authorizer(
        RequestVerifier(keys, audiences={TOOLS}),
        GrantVerifier(
            keys,
            root_policy=trust_principals({human.did: ["tools.*", "files.read"]}),
            revoked=RegistryRevocationChecker(reg, ttl=0),
        ),
    )
    svc = FastAPI()

    @svc.post("/search")
    def search(body: dict, who: AuthorizedAgent = Depends(require("tools.search"))):
        return {"agent": who.did, "principal": who.principal, "via": who.via, "q": body["q"]}

    @svc.post("/admin/wipe")
    def wipe(who: AuthorizedAgent = Depends(require("admin.wipe"))):
        return {"wiped": True}

    client = TestClient(svc, base_url=f"http://{TOOLS}")
    return dict(reg=reg, human=human, agent=agent, sub=sub, stranger=stranger, client=client)


def call(w, who, chain, path="/search", body=None):
    return w["client"].post(path, json=body or {"q": "hi"}, auth=who.httpx_auth(chain))


# --------------------------------------------------------------------------- #
# scope algebra
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "parent,child,ok",
    [
        ("*", "anything.at.all", True),
        ("tools.*", "tools.search", True),
        ("tools.*", "tools.web.fetch", True),
        ("tools.*", "tools.*", True),
        ("tools.*", "tools", False),
        ("tools.*", "toolsX.search", False),
        ("tools.search", "tools.search", True),
        ("tools.search", "tools.*", False),
        ("tools.search", "*", False),
    ],
)
def test_scope_covers(parent, child, ok):
    assert scope_covers(parent, child) is ok


# --------------------------------------------------------------------------- #
# direct grants
# --------------------------------------------------------------------------- #


def test_principal_grant_lets_agent_act(world):
    w = world
    chain = w["human"].grant(w["agent"].did, ["tools.search"], [TOOLS])
    r = call(w, w["agent"], chain)
    assert r.status_code == 200, r.text
    assert r.json()["principal"] == w["human"].did
    assert r.json()["via"] == [w["human"].did, w["agent"].did]


def test_no_grant_is_rejected(world):
    r = call(world, world["agent"], None)
    assert r.status_code == 401 and "no grant" in r.json()["detail"]


def test_scope_not_covered(world):
    w = world
    chain = w["human"].grant(w["agent"].did, ["tools.search"], [TOOLS])
    r = call(w, w["agent"], chain, path="/admin/wipe", body={})
    assert r.status_code == 403 and "admin.wipe" in r.json()["detail"]


def test_principal_cannot_grant_beyond_policy(world):
    w = world
    chain = w["human"].grant(w["agent"].did, ["*"], [TOOLS])  # policy only allows tools.*, files.read
    r = call(w, w["agent"], chain)
    assert r.status_code == 403 and "exceeds" in r.json()["detail"]


def test_untrusted_principal(world):
    w = world
    chain = w["stranger"].grant(w["agent"].did, ["tools.search"], [TOOLS])
    r = call(w, w["agent"], chain)
    assert r.status_code == 403 and "trust" in r.json()["detail"]


def test_stolen_grant_useless_to_other_agent(world):
    w = world
    chain = w["human"].grant(w["agent"].did, ["tools.search"], [TOOLS])
    r = call(w, w["stranger"], chain)  # stranger signs with its own key, presents agent's grant
    assert r.status_code == 403 and "different agent" in r.json()["detail"]


def test_wrong_audience(world):
    w = world
    chain = w["human"].grant(w["agent"].did, ["tools.search"], ["other.example"])
    r = call(w, w["agent"], chain)
    assert r.status_code == 403 and "audience" in r.json()["detail"]


def test_expired_grant(world):
    w = world
    chain = w["human"].grant(w["agent"].did, ["tools.search"], [TOOLS], ttl=60)
    verifier = GrantVerifier(
        RegistryKeyResolver(w["reg"], ttl=0), trust_principals({w["human"].did: ["tools.*"]})
    )
    verifier.verify(chain.encode(), requester=w["agent"].did, audience=TOOLS)
    with pytest.raises(GrantError, match="expired"):
        verifier.verify(chain.encode(), requester=w["agent"].did, audience=TOOLS, now=int(time.time()) + 3600)


def test_grant_header_is_bound_to_request_signature(world):
    w = world
    narrow = w["human"].grant(w["agent"].did, ["tools.search"], [TOOLS])
    other = w["human"].grant(w["agent"].did, ["tools.search"], [TOOLS])
    auth = w["agent"].authorization("POST", f"http://{TOOLS}/search", b'{"q":"x"}', narrow.encode())
    r = w["client"].post(
        "/search",
        content=b'{"q":"x"}',
        headers={"Authorization": auth, "AgentGrant": other.encode(), "Content-Type": "application/json"},
    )
    assert r.status_code == 401 and "signature" in r.json()["detail"]


def test_tampered_grant_rejected(world):
    w = world
    chain = w["human"].grant(w["agent"].did, ["tools.search"], [TOOLS])
    g = chain.links[0]
    body = copy.deepcopy(g.body)
    body["scope"] = ["tools.*", "files.read"]
    forged = GrantChain([Grant(body, g.sig)])
    r = call(w, w["agent"], forged)
    assert r.status_code == 403 and "signature" in r.json()["detail"]


# --------------------------------------------------------------------------- #
# delegation
# --------------------------------------------------------------------------- #


def test_delegation_chain(world):
    w = world
    root = w["human"].grant(w["agent"].did, ["tools.*"], [TOOLS], depth=1)
    chain = w["agent"].grant(w["sub"].did, ["tools.search"], [TOOLS], parent=root)
    assert len(chain.links) == 2 and chain.leaf.depth == 0
    r = call(w, w["sub"], chain)
    assert r.status_code == 200, r.text
    assert r.json()["via"] == [w["human"].did, w["agent"].did, w["sub"].did]


def test_delegation_requires_depth(world):
    w = world
    root = w["human"].grant(w["agent"].did, ["tools.*"], [TOOLS])  # depth=0
    with pytest.raises(GrantError, match="further delegation"):
        w["agent"].grant(w["sub"].did, ["tools.search"], [TOOLS], parent=root)


def test_delegation_cannot_widen_locally(world):
    w = world
    root = w["human"].grant(w["agent"].did, ["tools.search"], [TOOLS], depth=1)
    with pytest.raises(GrantError, match="scopes exceed"):
        w["agent"].grant(w["sub"].did, ["tools.*"], [TOOLS], parent=root)
    with pytest.raises(GrantError, match="audiences exceed"):
        w["agent"].grant(w["sub"].did, ["tools.search"], [TOOLS, "evil.example"], parent=root)


def test_hand_forged_widening_rejected_by_service(world):
    """Even if the delegating agent bypasses the SDK checks, the service catches it."""
    w = world
    root = w["human"].grant(w["agent"].did, ["tools.search"], [TOOLS], depth=1)
    body = {
        "v": "agentauth-grant/1", "id": "x" * 22, "iss": w["agent"].did, "kid": w["agent"].kid,
        "sub": w["sub"].did, "scope": ["tools.*"], "aud": [TOOLS],
        "nbf": root.leaf.nbf, "exp": root.leaf.exp, "depth": 0, "parent": root.leaf.id,
    }
    evil = GrantChain(root.links + [Grant(body, w["agent"].current_key.sign(canonical_json(body)))])
    r = call(w, w["sub"], evil)
    assert r.status_code == 403 and "widens" in r.json()["detail"]


def test_child_cannot_outlive_parent(world):
    w = world
    root = w["human"].grant(w["agent"].did, ["tools.*"], [TOOLS], ttl=120, depth=1)
    child = w["agent"].grant(w["sub"].did, ["tools.search"], [TOOLS], ttl=3600, parent=root)
    assert child.leaf.exp == root.leaf.exp  # clamped


def test_missing_root_rejected(world):
    w = world
    root = w["human"].grant(w["agent"].did, ["tools.*"], [TOOLS], depth=1)
    chain = w["agent"].grant(w["sub"].did, ["tools.search"], [TOOLS], parent=root)
    r = call(w, w["sub"], GrantChain(chain.links[1:]))
    assert r.status_code == 403


# --------------------------------------------------------------------------- #
# revocation & cascade
# --------------------------------------------------------------------------- #


def test_revoking_parent_kills_delegations(world):
    w = world
    root = w["human"].grant(w["agent"].did, ["tools.*"], [TOOLS], depth=1)
    chain = w["agent"].grant(w["sub"].did, ["tools.search"], [TOOLS], parent=root)
    assert call(w, w["sub"], chain).status_code == 200

    w["reg"].revoke_grant(w["human"], root.leaf.id)
    assert call(w, w["agent"], root).status_code == 403
    r = call(w, w["sub"], chain)
    assert r.status_code == 403 and "revoked" in r.json()["detail"]


def test_only_issuer_can_revoke(world):
    w = world
    root = w["human"].grant(w["agent"].did, ["tools.*"], [TOOLS])
    w["reg"].revoke_grant(w["stranger"], root.leaf.id)  # recorded under stranger — no effect
    assert call(w, w["agent"], root).status_code == 200


def test_deactivating_middle_agent_cascades(world):
    w = world
    root = w["human"].grant(w["agent"].did, ["tools.*"], [TOOLS], depth=1)
    chain = w["agent"].grant(w["sub"].did, ["tools.search"], [TOOLS], parent=root)
    w["reg"].deactivate_controlled(w["human"], w["agent"].did)  # kill switch on the researcher
    r = call(w, w["sub"], chain)
    assert r.status_code == 403 and "deactivated" in r.json()["detail"]


def test_issuer_rotation_requires_reissue(world):
    w = world
    root = w["human"].grant(w["agent"].did, ["tools.*"], [TOOLS])
    w["reg"].rotate(w["human"])
    r = call(w, w["agent"], root)
    assert r.status_code == 403 and "re-issue" in r.json()["detail"]
    fresh = w["human"].grant(w["agent"].did, ["tools.*"], [TOOLS])
    assert call(w, w["agent"], fresh).status_code == 200

import copy
import json
import os
import stat
import time

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from agentauth import (
    AgentIdentity,
    AuthError,
    KeyPair,
    RegistryClient,
    RegistryError,
    RegistryKeyResolver,
    RequestVerifier,
    verify_log,
)
from agentauth.crypto import b58decode, b58encode, canonical_json, multikey_to_public_key
from agentauth.identity import InvalidEvent, make_rotation, verify_inception
from agentauth.integrations import fastapi_dependency
from agentauth.server import create_app


@pytest.fixture
def registry(tmp_path):
    app = create_app(db_path=str(tmp_path / "reg.db"), audiences={"testserver"})
    http = TestClient(app)
    return RegistryClient("http://testserver", client=http), http


def new_agent(reg, **kw):
    ident, event = AgentIdentity.create(**kw)
    reg.register(event)
    return ident


# --------------------------------------------------------------------------- #
# primitives
# --------------------------------------------------------------------------- #


def test_base58_roundtrip():
    for data in [b"", b"\x00\x00abc", os.urandom(34)]:
        assert b58decode(b58encode(data)) == data


def test_multikey_is_standard_ed25519_prefix():
    kp = KeyPair.generate()
    assert kp.public_multikey.startswith("z6Mk")  # same encoding as did:key
    assert multikey_to_public_key(kp.public_multikey) == kp.public_bytes


def test_canonical_json_rejects_floats():
    with pytest.raises(TypeError):
        canonical_json({"a": 1.5})
    assert canonical_json({"b": 1, "a": [True, None]}) == b'{"a":[true,null],"b":1}'


# --------------------------------------------------------------------------- #
# identity / key event log
# --------------------------------------------------------------------------- #


def test_did_is_self_certifying():
    ident, event = AgentIdentity.create(name="alpha")
    assert ident.did.startswith("did:agent:")
    tampered = copy.deepcopy(event)
    tampered["body"]["meta"]["name"] = "evil"
    with pytest.raises(InvalidEvent):
        verify_inception(tampered, lambda d, k: True)


def test_register_resolve_and_whoami(registry):
    reg, _ = registry
    agent = new_agent(reg, name="researcher", meta={"model": "claude"})
    doc = reg.resolve(agent.did)
    assert doc["didDocument"]["id"] == agent.did
    assert doc["didDocument"]["verificationMethod"][0]["publicKeyMultibase"] == agent.current_key.public_multikey
    assert doc["didDocument"]["agent"] == {"model": "claude", "name": "researcher"}
    assert reg.whoami(agent) == {"did": agent.did, "kid": f"{agent.did}#key-0"}


def test_duplicate_registration_conflicts(registry):
    reg, _ = registry
    ident, event = AgentIdentity.create(name="x")
    reg.register(event)
    with pytest.raises(RegistryError) as e:
        reg.register(event)
    assert e.value.status == 409


def test_rotation_uses_precommitted_key(registry):
    reg, _ = registry
    agent = new_agent(reg, name="rotator")
    old_key, precommitted = agent.current_key.public_multikey, agent.recovery_key.public_multikey
    reg.rotate(agent)
    assert agent.current_key.public_multikey == precommitted != old_key
    assert agent.kid.endswith("#key-1")
    assert reg.whoami(agent)["kid"] == agent.kid
    state = verify_log(reg.log(agent.did))
    assert state.seq == 1 and state.key == precommitted


def test_stolen_current_key_cannot_rotate(registry):
    reg, _ = registry
    agent = new_agent(reg, name="victim")
    attacker_next = KeyPair.generate()
    # attacker holds the current key but not the pre-committed recovery key
    evil = make_rotation(agent.state, agent.current_key, attacker_next)
    with pytest.raises(RegistryError) as e:
        reg.submit(agent.did, evil)
    assert "pre-rotation" in e.value.detail


def test_old_key_rejected_after_rotation(registry):
    reg, http = registry
    agent = new_agent(reg, name="a")
    old = AgentIdentity(copy.deepcopy(agent.state), agent.current_key, None)
    reg.rotate(agent)
    r = http.get("/v1/whoami", auth=old.httpx_auth())
    assert r.status_code == 401


def test_self_deactivation(registry):
    reg, http = registry
    agent = new_agent(reg, name="doomed")
    stale = AgentIdentity(copy.deepcopy(agent.state), agent.current_key, None)
    reg.deactivate_self(agent)
    meta = reg.resolve(agent.did)
    assert meta["didDocumentMetadata"]["deactivated"] is True
    assert meta["didDocument"]["verificationMethod"] == []
    assert http.get("/v1/whoami", auth=stale.httpx_auth()).status_code == 401
    with pytest.raises(RuntimeError):
        agent.authorization("GET", "http://testserver/v1/whoami")


def test_controller_kill_switch(registry):
    reg, http = registry
    human = new_agent(reg, name="arunima")
    worker = new_agent(reg, name="worker", controller=human)
    assert reg.controlled_agents(human.did) == [{"did": worker.did, "active": True}]

    stranger = new_agent(reg, name="stranger")
    with pytest.raises(ValueError):
        stranger.prepare_deactivation_of(reg.verified_state(worker.did))

    reg.deactivate_controlled(human, worker.did)
    assert reg.resolve(worker.did)["didDocumentMetadata"]["deactivated"] is True
    assert http.get("/v1/whoami", auth=worker.httpx_auth()).status_code == 401


def test_controller_must_countersign(registry):
    reg, _ = registry
    human = new_agent(reg, name="owner")
    impostor = KeyPair.generate()
    ident, event = AgentIdentity.create(name="squatter", controller=human)
    event["controller_proof"]["sig"] = impostor.sign(canonical_json(event["body"]))
    with pytest.raises(RegistryError):
        reg.register(event)


def test_log_tampering_detected(registry):
    reg, _ = registry
    agent = new_agent(reg, name="t")
    reg.rotate(agent)
    log = reg.log(agent.did)
    log[1]["body"]["ts"] = "2000-01-01T00:00:00Z"
    with pytest.raises(InvalidEvent):
        verify_log(log)


# --------------------------------------------------------------------------- #
# request signing
# --------------------------------------------------------------------------- #


def test_replay_and_tampering_rejected(registry):
    reg, http = registry
    agent = new_agent(reg, name="r")
    auth = agent.authorization("GET", "http://testserver/v1/whoami")
    assert http.get("/v1/whoami", headers={"Authorization": auth}).status_code == 200
    replay = http.get("/v1/whoami", headers={"Authorization": auth})
    assert replay.status_code == 401 and "replayed" in replay.json()["detail"]
    other_path = agent.authorization("GET", "http://testserver/v1/other")
    assert http.get("/v1/whoami", headers={"Authorization": other_path}).status_code == 401


def test_wrong_audience_rejected(registry):
    reg, http = registry
    agent = new_agent(reg, name="aud")
    auth = agent.authorization("GET", "http://some-other-service.example/v1/whoami")
    r = http.get("/v1/whoami", headers={"Authorization": auth})
    assert r.status_code == 401 and "audience" in r.json()["detail"]


def test_stale_timestamp_rejected():
    kp = KeyPair.generate()
    v = RequestVerifier(lambda did: (kp.public_multikey, "did:agent:x#key-0"), audiences={"svc"})
    from agentauth.httpsig import sign_request

    auth = sign_request(did="did:agent:x", kid="did:agent:x#key-0", key=kp, method="GET",
                        url="http://svc/a", ts=int(time.time()) - 3600)
    with pytest.raises(AuthError, match="window"):
        v.verify(authorization=auth, method="GET", path="/a", body=b"")


def test_body_is_covered_by_signature(registry):
    reg, _ = registry
    agent = new_agent(reg, name="body")
    kp = agent.current_key
    v = RequestVerifier(lambda d: (kp.public_multikey, agent.kid), audiences={"svc"})
    auth = agent.authorization("POST", "http://svc/pay", b'{"amount": 10}')
    with pytest.raises(AuthError, match="signature"):
        v.verify(authorization=auth, method="POST", path="/pay", body=b'{"amount": 10000}')


def test_third_party_service_verifies_via_registry(registry):
    """A separate service trusts agents by resolving them through the registry."""
    reg, _ = registry
    agent = new_agent(reg, name="caller")

    resolver = RegistryKeyResolver(reg, ttl=300)
    svc = FastAPI()
    require_agent = fastapi_dependency(RequestVerifier(resolver, audiences={"tools.example"}))

    @svc.post("/tools/search")
    def search(payload: dict, caller=Depends(require_agent)):
        return {"caller": caller.did, "q": payload["q"]}

    client = TestClient(svc, base_url="http://tools.example")
    r = client.post("/tools/search", json={"q": "agents"}, auth=agent.httpx_auth())
    assert r.status_code == 200 and r.json() == {"caller": agent.did, "q": "agents"}

    # Rotate: the service's cache still holds key-0, but a newer kid forces a refresh.
    reg.rotate(agent)
    r = client.post("/tools/search", json={"q": "again"}, auth=agent.httpx_auth())
    assert r.status_code == 200

    unknown, _ = AgentIdentity.create(name="unregistered")
    r = client.post("/tools/search", json={"q": "x"}, auth=unknown.httpx_auth())
    assert r.status_code == 401


# --------------------------------------------------------------------------- #
# keystore
# --------------------------------------------------------------------------- #


def test_save_load_encrypted_and_split(tmp_path, registry):
    reg, _ = registry
    agent = new_agent(reg, name="persist")
    keys, vault = tmp_path / "keys", tmp_path / "vault"
    agent.save(keys, "persist", passphrase="hunter2", recovery_dir=vault)

    key_file = keys / "persist.key.json"
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    assert agent.current_key.public_multikey in key_file.read_text()
    assert "seed" not in json.loads(key_file.read_text())["secret"]  # encrypted
    assert not (keys / "persist.recovery.json").exists()

    with pytest.raises(Exception):
        AgentIdentity.load(keys, "persist", passphrase="wrong")

    runtime = AgentIdentity.load(keys, "persist", passphrase="hunter2")  # no vault access
    assert runtime.recovery_key is None and reg.whoami(runtime)["did"] == agent.did
    with pytest.raises(RuntimeError):
        runtime.prepare_rotation()

    admin = AgentIdentity.load(keys, "persist", passphrase="hunter2", recovery_dir=vault)
    reg.rotate(admin)
    assert reg.whoami(admin)["kid"].endswith("#key-1")


# --------------------------------------------------------------------------- #
# client compatibility
# --------------------------------------------------------------------------- #


def test_auth_works_with_plain_httpx_client():
    """TestClient uses httpx2 when installed; make sure plain httpx clients are still supported."""
    import httpx

    ident, _ = AgentIdentity.create(name="plain")
    verifier = RequestVerifier(lambda d: (ident.current_key.public_multikey, ident.kid), audiences={"svc.example"})

    def handler(request: httpx.Request) -> httpx.Response:
        agent = verifier.verify(
            authorization=request.headers["authorization"],
            method=request.method,
            path=request.url.raw_path.decode(),
            body=request.content,
        )
        return httpx.Response(200, json={"did": agent.did})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        r = client.post("http://svc.example/do?x=1", json={"a": 1}, auth=ident.httpx_auth())
    assert r.json() == {"did": ident.did}


def test_auth_is_callable_for_httpx2_style_clients():
    ident, _ = AgentIdentity.create(name="callable")
    import httpx

    req = httpx.Request("GET", "http://svc.example/x")
    signed = ident.httpx_auth()(req)
    assert signed is req and req.headers["authorization"].startswith("AgentSig ")

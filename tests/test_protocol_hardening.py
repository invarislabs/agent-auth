"""Adversarial inputs to the primitives, the key event log and request authentication.

Every malformed input must be *rejected* (4xx / exception), never accepted and
never crash the registry (5xx).
"""

import copy
import json
import random
import time

import pytest
from conftest import new_agent

from agentauth import AgentIdentity, AuthError, KeyPair, RequestVerifier
from agentauth.crypto import b64u, b64u_decode, canonical_json, is_digest, verify
from agentauth.httpsig import NonceCache, ReplayCacheUnavailable, parse_authorization, sign_request
from agentauth.identity import InvalidEvent, apply_event, make_rotation, verify_inception, verify_log

# --------------------------------------------------------------------------- #
# primitives
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("bad", ["abc=", "ab+c", "ab/c", "a b", "a", "AB\n", "AQ==", "AR"])
def test_b64u_is_strict(bad):
    with pytest.raises(ValueError):
        b64u_decode(bad)


def test_b64u_roundtrip_and_signature_malleability():
    kp = KeyPair.generate()
    sig = kp.sign(b"m")
    assert b64u(b64u_decode(sig)) == sig and verify(kp.public_multikey, b"m", sig)
    # Alternative encodings of the same bytes (stray characters, padding) are not valid signatures.
    for alt in (sig + "=", sig[:10] + "!" + sig[10:], " " + sig):
        assert not verify(kp.public_multikey, b"m", alt)


def test_verify_never_raises():
    kp = KeyPair.generate()
    for key in (None, 5, "", "z", "zzzz", "x" * 1000, kp.public_multikey):
        for sig in (None, 5, "", "!!!", "A" * 86, b64u(b"\x00" * 64)):
            assert verify(key, b"m", sig) is False


def test_canonical_json_rejects_unencodable_strings():
    with pytest.raises(TypeError):
        canonical_json({"a": "\ud800"})


def test_is_digest():
    from agentauth.crypto import digest

    assert is_digest(digest(b"x"))
    for bad in (None, "", "z", "zabc", "Q" + digest(b"x")[1:], digest(b"x") + "1"):
        assert not is_digest(bad)


# --------------------------------------------------------------------------- #
# key event log
# --------------------------------------------------------------------------- #


def _mutations(event):
    """Yield structurally broken variants of a valid signed event."""
    body = event["body"]
    for k in list(body):
        e = copy.deepcopy(event)
        del e["body"][k]
        yield f"drop {k}", e
        for v in (None, 1.5, True, [], {}, "x" * 3000, -1):
            if v == body[k] and type(v) is type(body[k]):
                continue  # not a mutation
            e = copy.deepcopy(event)
            e["body"][k] = v
            yield f"{k}={v!r:.20}", e
    e = copy.deepcopy(event)
    e["body"]["extra"] = "field"
    yield "unknown body field", e
    e = copy.deepcopy(event)
    e["extra"] = 1
    yield "unknown envelope field", e
    for k in ("sig", "signer"):
        for v in (None, 5, "", []):
            e = copy.deepcopy(event)
            e[k] = v
            yield f"{k}={v!r}", e


def test_inception_mutations_all_rejected():
    _, event = AgentIdentity.create(name="m")
    verify_inception(event, lambda d, k: True)
    for label, bad in _mutations(event):
        with pytest.raises(InvalidEvent):
            verify_inception(bad, lambda d, k: True)
            pytest.fail(f"accepted mutated inception: {label}")


def test_rotation_mutations_all_rejected():
    ident, _ = AgentIdentity.create(name="m")
    good = make_rotation(ident.state, ident.recovery_key, KeyPair.generate())
    apply_event(ident.state, good, lambda d, k: True)
    for label, bad in _mutations(good):
        with pytest.raises(InvalidEvent):
            apply_event(ident.state, bad, lambda d, k: True)
            pytest.fail(f"accepted mutated rotation: {label}")


def test_controller_proof_only_with_controller():
    ident, event = AgentIdentity.create(name="lone")
    event["controller_proof"] = {"key": ident.current_key.public_multikey, "sig": "x"}
    with pytest.raises(InvalidEvent, match="controller_proof"):
        verify_inception(event, lambda d, k: True)


def test_float_in_meta_is_rejected_not_crash(registry):
    reg, http = registry
    _, event = AgentIdentity.create(name="f")
    raw = json.dumps(event).replace('"name": "f"', '"name": "f", "weight": 1.5')
    r = http.post("/v1/identities", content=raw, headers={"content-type": "application/json"})
    assert r.status_code == 400


def test_registry_never_500s_on_garbage(registry):
    """Throw a few hundred random shapes at every write endpoint."""
    reg, http = registry
    agent = new_agent(reg, name="target")
    rnd = random.Random(1234)
    atoms = [None, True, 0, -1, 2**63, 1.5, "", "x", "did:agent:x", [], {}, agent.did, agent.state.key]

    def junk(depth=0):
        r = rnd.random()
        if depth > 3 or r < 0.4:
            return rnd.choice(atoms)
        if r < 0.7:
            return [junk(depth + 1) for _ in range(rnd.randint(0, 3))]
        keys = ["body", "sig", "signer", "v", "type", "seq", "key", "next", "did", "prev", "ts", "grants", "iss", "grant"]
        return {rnd.choice(keys): junk(depth + 1) for _ in range(rnd.randint(0, 5))}

    for _ in range(300):
        payload = junk()
        for path in ("/v1/identities", f"/v1/identities/{agent.did}/events", "/v1/revocations",
                     "/v1/revocations/check"):
            r = http.post(path, json=payload)
            assert r.status_code < 500, (path, payload, r.text)
    for raw in (b"", b"{", b"[1,", b'{"a":NaN}', b'{"a":1,"a":2}', b"\xff\xfe", b"[" * 5000 + b"]" * 5000):
        r = http.post("/v1/identities", content=raw, headers={"content-type": "application/json"})
        assert 400 <= r.status_code < 500, (raw[:20], r.status_code)


def test_log_with_reordered_or_duplicated_events_rejected(registry):
    reg, _ = registry
    agent = new_agent(reg, name="o")
    reg.rotate(agent)
    reg.rotate(agent)
    log = reg.log(agent.did)
    for bad in ([log[0], log[2], log[1]], [log[0], log[1], log[1]], log[1:], [log[0]] + log):
        with pytest.raises(InvalidEvent):
            verify_log(bad)


# --------------------------------------------------------------------------- #
# request authentication
# --------------------------------------------------------------------------- #


def _verifier(ident, **kw):
    return RequestVerifier(lambda d: (ident.current_key.public_multikey, ident.kid) if d == ident.did else None,
                           audiences={"svc"}, **kw)


def _parts(header):
    return parse_authorization(header)


def _rebuild(p):
    return "AgentSig " + ",".join(f'{k}="{v}"' for k, v in p.items())


@pytest.mark.parametrize("header", [
    "", "Bearer abc", "AgentSig", "AgentSig ", 'AgentSig did="a"',
    'AgentSig did="a",did="b",kid="k",aud="svc",ts="1",nonce="n",sig="s"',
    'AgentSig did="a" kid="k"', 'AgentSig did=a,kid="k"', "AgentSig " + "x" * 5000,
])
def test_malformed_headers(header):
    with pytest.raises(AuthError):
        parse_authorization(header)


def test_duplicate_parameter_cannot_smuggle_identity():
    ident, _ = AgentIdentity.create(name="dup")
    other, _ = AgentIdentity.create(name="other")
    h = ident.authorization("GET", "http://svc/x")
    smuggled = h + f',did="{other.did}"'
    with pytest.raises(AuthError, match="duplicate"):
        _verifier(ident).verify(authorization=smuggled, method="GET", path="/x", body=b"")


@pytest.mark.parametrize("ts", ["+{}", " {}", "{}_0", "{}.0", "-{}", "0x10", "", "{}0000000000000"])
def test_noncanonical_timestamps_rejected(ts):
    ident, _ = AgentIdentity.create(name="ts")
    now = int(time.time())
    p = _parts(ident.authorization("GET", "http://svc/x"))
    p["ts"] = ts.format(now)
    with pytest.raises(AuthError):
        _verifier(ident).verify(authorization=_rebuild(p), method="GET", path="/x", body=b"")


def test_short_nonce_rejected():
    ident, _ = AgentIdentity.create(name="n")
    h = sign_request(did=ident.did, kid=ident.kid, key=ident.current_key, method="GET", url="http://svc/x", nonce="abc")
    with pytest.raises(AuthError, match="nonce"):
        _verifier(ident).verify(authorization=h, method="GET", path="/x", body=b"")


def test_kid_must_belong_to_did():
    ident, _ = AgentIdentity.create(name="k")
    other, _ = AgentIdentity.create(name="o")
    h = sign_request(did=ident.did, kid=other.kid, key=ident.current_key, method="GET", url="http://svc/x")
    with pytest.raises(AuthError, match="kid"):
        _verifier(ident).verify(authorization=h, method="GET", path="/x", body=b"")


def test_method_query_and_grant_header_are_covered():
    ident, _ = AgentIdentity.create(name="cov")
    v = _verifier(ident)
    h = ident.authorization("GET", "http://svc/x?a=1")
    for kw in (dict(method="DELETE", path="/x?a=1"), dict(method="GET", path="/x?a=2"),
               dict(method="GET", path="/x?a=1", grants="g")):
        with pytest.raises(AuthError, match="signature"):
            v.verify(authorization=h, body=b"", **kw)
    v.verify(authorization=h, method="get", path="/x?a=1", body=b"")


def test_userinfo_urls_refused_by_signer():
    ident, _ = AgentIdentity.create(name="u")
    with pytest.raises(ValueError):
        ident.authorization("GET", "http://user:pw@svc/x")


def test_resolver_failure_is_503_not_401_or_500():
    ident, _ = AgentIdentity.create(name="down")

    def broken(did):
        raise ConnectionError("registry unreachable")

    v = RequestVerifier(broken, audiences={"svc"})
    with pytest.raises(AuthError) as e:
        v.verify(authorization=ident.authorization("GET", "http://svc/x"), method="GET", path="/x", body=b"")
    assert e.value.status == 503


def test_replay_cache_failure_fails_closed():
    ident, _ = AgentIdentity.create(name="rc")

    class Broken:
        def check_and_store(self, did, nonce):
            raise ConnectionError("redis down")

    v = _verifier(ident, nonce_cache=Broken())
    with pytest.raises(AuthError) as e:
        v.verify(authorization=ident.authorization("GET", "http://svc/x"), method="GET", path="/x", body=b"")
    assert e.value.status == 503


def test_nonce_cache_bounded_and_expiring(monkeypatch):
    c = NonceCache(ttl=10, max_entries=3)
    t = [1000.0]
    monkeypatch.setattr("agentauth.httpsig.time.time", lambda: t[0])
    assert all(c.check_and_store("d", f"n{i}") for i in range(3))
    with pytest.raises(ReplayCacheUnavailable):
        c.check_and_store("d", "n4")  # full of live entries: refuse rather than forget
    assert c.check_and_store("d", "n0") is False
    t[0] += 11
    assert c.check_and_store("d", "n0") is True  # expired entries are pruned
    assert len(c) == 1


def test_forced_refresh_is_rate_limited(registry):
    """Presenting a higher kid forces a registry refresh, but not more than once per interval."""
    from agentauth import RegistryKeyResolver

    reg, _ = registry
    agent = new_agent(reg, name="hammer")
    calls = []
    orig = reg.log

    def counting_log(did):
        calls.append(did)
        return orig(did)

    reg.log = counting_log
    keys = RegistryKeyResolver(reg, ttl=300, min_refresh_interval=60)
    v = RequestVerifier(keys, audiences={"svc"})
    for _ in range(20):
        h = sign_request(did=agent.did, kid=agent.did + "#key-99", key=agent.current_key, method="GET",
                         url="http://svc/x")
        with pytest.raises(AuthError):
            v.verify(authorization=h, method="GET", path="/x", body=b"")
    assert len(calls) == 2  # initial fetch + one forced refresh

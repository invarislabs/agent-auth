"""Run the cross-implementation test vectors (test-vectors/*.json) against this implementation.

The TypeScript verifier in ts/ runs the same files. If both pass, they accept
and reject exactly the same inputs.
"""

import base64
import json
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

from agentauth.crypto import (
    b58decode,
    b58encode,
    canonical_json,
    digest,
    key_commitment,
    public_key_to_multikey,
    verify,
)
from agentauth.grants import (
    GrantError,
    GrantVerifier,
    audience_covers,
    scope_covers,
    trust_principals,
    verify_revocation,
)
from agentauth.httpsig import AuthError, RequestVerifier, signing_string
from agentauth.identity import InvalidEvent, verify_log
from agentauth.limits import LimitError, Limits, pattern_covers, pattern_matches

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "test-vectors"


def load(name: str) -> dict:
    data = json.loads((VECTORS / name).read_text())
    assert data["format"] == "agentauth-test-vectors/1"
    return data


def test_vectors_are_current():
    """The committed vectors match what the generator produces from this code."""
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "generate_test_vectors.py"), "--check"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


# --------------------------------------------------------------------------- #

P = load("primitives.json")


@pytest.mark.parametrize("c", P["base58btc"])
def test_base58(c):
    raw = base64.b64decode(c["bytes_b64"])
    assert b58encode(raw) == c["encoded"] and b58decode(c["encoded"]) == raw


def test_multikey_digest_commitment():
    for c in P["multikey"]:
        assert public_key_to_multikey(base64.b64decode(c["public_key_b64"])) == c["multikey"]
    for c in P["digest"]:
        assert digest(base64.b64decode(c["input_b64"])) == c["digest"]
    for c in P["key_commitment"]:
        assert key_commitment(c["multikey"]) == c["commitment"]


@pytest.mark.parametrize("c", P["canonical_json"])
def test_canonical_json(c):
    assert canonical_json(json.loads(c["json"])).decode() == c["canonical"]


@pytest.mark.parametrize("c", P["canonical_json_invalid"])
def test_canonical_json_invalid(c):
    with pytest.raises(TypeError):
        canonical_json(json.loads(c["json"]))


@pytest.mark.parametrize("c", P["signatures"], ids=lambda c: c.get("reason", "valid"))
def test_signatures(c):
    assert verify(c["multikey"], base64.b64decode(c["message_b64"]), c["signature"]) is c["valid"]


# --------------------------------------------------------------------------- #

K = load("kel.json")


@pytest.mark.parametrize("c", K["cases"], ids=lambda c: c["name"])
def test_kel(c):
    if not c["valid"]:
        with pytest.raises(InvalidEvent):
            verify_log(c["log"])
        return
    st = verify_log(c["log"])
    want = c["state"]
    assert (st.did, st.seq, st.active, st.key, st.next, st.controller, st.last_digest) == (
        want["did"], want["seq"], want["active"], want["key"], want["next"], want["controller"], want["last_digest"])
    assert (st.key_id if st.active else None) == want["kid"]
    if "valid_with_controller_binding" in c:
        ctrl = verify_log(next(x for x in K["cases"] if x["name"] == c["controller_log"])["log"])
        keys = {ctrl.did: {k for _, k in ctrl.history}}

        def bound(d, k):
            return k in keys.get(d, set())

        if c["valid_with_controller_binding"]:
            verify_log(c["log"], bound)
        else:
            with pytest.raises(InvalidEvent):
                verify_log(c["log"], bound)


# --------------------------------------------------------------------------- #

R = load("requests.json")


def test_signing_string():
    for c in R["signing_string"]:
        got = signing_string(c["method"], c["audience"], c["path"], c["ts"], c["nonce"],
                             base64.b64decode(c["body_b64"]), c["grants"])
        assert got.decode() == c["signing_string"]


@pytest.mark.parametrize("c", R["cases"], ids=lambda c: c["name"])
def test_requests(c):
    keys = R["keys"]
    seen: set = set()

    class Nonces:
        ttl = 10_000

        def check_and_store(self, did, nonce):
            fresh = (did, nonce) not in seen
            seen.add((did, nonce))
            return fresh

    v = RequestVerifier(lambda d: (keys[d]["key"], keys[d]["kid"]) if d in keys else None,
                        audiences=set(R["audiences"]), max_skew=R["max_skew"], nonce_cache=Nonces())
    got = []
    with mock.patch("agentauth.httpsig.time.time", lambda: c["now"]):
        for _ in range(c["repeat"]):
            try:
                a = v.verify(authorization=c["authorization"], method=c["method"], path=c["path"],
                             body=base64.b64decode(c["body_b64"]), grants=c["grants"])
                got.append({"valid": True, "did": a.did, "kid": a.kid})
            except AuthError as e:
                got.append({"valid": False, "status": e.status})
    assert got == c["expect"]


# --------------------------------------------------------------------------- #

G = load("grants.json")


@pytest.mark.parametrize("c", G["cases"], ids=lambda c: c["name"])
def test_grants(c):
    keys = G["keys"]
    revoked = {tuple(r) for r in c["revoked"]}
    gv = GrantVerifier(lambda d: (keys[d]["key"], keys[d]["kid"]) if d in keys else None,
                       trust_principals(G["root_policy"]), revoked=lambda pairs: {tuple(p) for p in pairs} & revoked)
    if not c["expect"]["valid"]:
        with pytest.raises(GrantError) as e:
            gv.verify(c["header"], requester=c["requester"], audience=c["audience"], now=c["now"])
        assert e.value.status == c["expect"]["status"]
        return
    a = gv.verify(c["header"], requester=c["requester"], audience=c["audience"], now=c["now"])
    want = c["expect"]
    assert (a.principal, a.via, a.scopes, a.grant_ids, a.limits) == (
        want["principal"], want["via"], want["scopes"], want["grant_ids"], want["leaf_limits"])


def test_scope_and_audience_algebra():
    for c in G["scope_covers"]:
        assert scope_covers(c["parent"], c["child"]) is c["covers"]
    for c in G["audience_covers"]:
        assert audience_covers(c["parents"], c["children"]) is c["covers"]


# --------------------------------------------------------------------------- #

L = load("limits.json")


def test_limits():
    for c in L["narrowing"]:
        got = Limits.from_dict(c["parent"]).narrowing_violation(Limits.from_dict(c["child"])) is not None
        assert got is c["violation"], c
    for c in L["invalid"]:
        with pytest.raises(LimitError):
            Limits.from_dict(c["limits"])
    for c in L["check_call"]:
        try:
            Limits.from_dict(c["limits"]).check_call(resource=c["resource"], amount=c["amount"], unit=c["unit"])
            got = {"valid": True}
        except LimitError as e:
            got = {"valid": False, "status": e.status}
        assert got == c["expect"], c
    for c in L["pattern_matches"]:
        assert pattern_matches(c["pattern"], c["resource"]) is c["matches"]
    for c in L["pattern_covers"]:
        assert pattern_covers(c["parent"], c["child"]) is c["covers"]


# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("c", load("revocations.json")["cases"], ids=lambda c: c["name"])
def test_revocations(c):
    if c["valid"]:
        verify_revocation(c["event"], c["issuer_key"])
    else:
        with pytest.raises(GrantError):
            verify_revocation(c["event"], c["issuer_key"])

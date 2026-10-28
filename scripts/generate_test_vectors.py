"""Generate the cross-implementation test vectors in test-vectors/.

    python scripts/generate_test_vectors.py            # rewrite test-vectors/*.json
    python scripts/generate_test_vectors.py --check    # exit 1 if the files are stale

Everything is deterministic: keys come from fixed seeds, timestamps and grant
ids are pinned. Every case declares what a conforming verifier must do
(accept, or reject with a given HTTP status), and the generator first checks
that this Python implementation agrees, so a vector can never silently encode
a bug. See test-vectors/README.md for the format.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import agentauth.grants as grants_mod  # noqa: E402
import agentauth.identity as identity_mod  # noqa: E402
from agentauth.crypto import (  # noqa: E402
    KeyPair,
    b58encode,
    b64u,
    canonical_json,
    digest,
    key_commitment,
)
from agentauth.grants import (  # noqa: E402
    Grant,
    GrantChain,
    GrantError,
    GrantVerifier,
    audience_covers,
    make_revocation,
    scope_covers,
    trust_principals,
    verify_revocation,
)
from agentauth.httpsig import AuthError, RequestVerifier, sign_request, signing_string  # noqa: E402
from agentauth.identity import (  # noqa: E402
    InvalidEvent,
    make_deactivation,
    make_inception,
    make_rotation,
    verify_inception,
    verify_log,
)
from agentauth.limits import LimitError, Limits, pattern_covers, pattern_matches  # noqa: E402

OUT = ROOT / "test-vectors"
NOW = 1_800_000_000  # 2027-01-15T08:00:00Z: the "current time" for every vector
TS = "2027-01-15T08:00:00Z"
FORMAT = "agentauth-test-vectors/1"


def kp(label: str) -> KeyPair:
    return KeyPair.from_seed(hashlib.sha256(f"agentauth-test-vector:{label}".encode()).digest())


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


class Pinned:
    """Pin the clock and grant ids so every run produces identical output."""

    def __init__(self):
        self.counter = 0

    def grant_id(self) -> str:
        self.counter += 1
        return b64u(hashlib.sha256(f"grant-{self.counter}".encode()).digest()[:16]).replace("-", "A")

    def __enter__(self):
        self.patches = [
            mock.patch.object(identity_mod, "now_iso", lambda: TS),
            mock.patch.object(grants_mod, "new_grant_id", self.grant_id),
            mock.patch.object(grants_mod.time, "time", lambda: NOW),
        ]
        for p in self.patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in self.patches:
            p.stop()


def expect_raises(fn: Callable[[], Any], exc: type, label: str) -> Exception:
    try:
        fn()
    except exc as e:
        return e
    raise SystemExit(f"generator bug: vector {label!r} was expected to be rejected but Python accepted it")


# --------------------------------------------------------------------------- #
# primitives
# --------------------------------------------------------------------------- #


def primitives() -> dict:
    k = kp("primitives")
    msg = b"agentauth"
    raw_cases = [b"", b"\x00", b"\x00\x00\x01", b"hello world", bytes(range(32))]
    return {
        "base58btc": [{"bytes_b64": b64(d), "encoded": b58encode(d)} for d in raw_cases],
        "multikey": [{"public_key_b64": b64(k.public_bytes), "multikey": k.public_multikey}],
        "digest": [
            {"input_b64": b64(d), "digest": digest(d)} for d in [b"", b"abc", canonical_json({"a": 1})]
        ],
        "key_commitment": [{"multikey": k.public_multikey, "commitment": key_commitment(k.public_multikey)}],
        "canonical_json": [
            {"json": '{"b":1,"a":[true,null,"x"],"c":{"z":0,"y":-5}}',
             "canonical": canonical_json({"b": 1, "a": [True, None, "x"], "c": {"z": 0, "y": -5}}).decode()},
            {"json": '{"k":"caf\\u00e9 \\ud83d\\ude00 \\"q\\" \\\\ \\n\\t\\u0001"}',
             "canonical": canonical_json({"k": 'café 😀 "q" \\ \n\t\x01'}).decode()},
            {"json": '{"\\u00e9":1,"z":2,"a":3,"\\ud83d\\ude00":4,"\\uffff":5}',
             "canonical": canonical_json({"é": 1, "z": 2, "a": 3, "😀": 4, "￿": 5}).decode()},
        ],
        "canonical_json_invalid": [
            {"json": '{"a":1.5}', "reason": "floats are not allowed"},
            {"json": '{"a":1e3}', "reason": "floats are not allowed"},
        ],
        "signatures": [
            {"multikey": k.public_multikey, "message_b64": b64(msg), "signature": k.sign(msg), "valid": True},
            {"multikey": k.public_multikey, "message_b64": b64(b"other"), "signature": k.sign(msg), "valid": False,
             "reason": "signature over a different message"},
            {"multikey": k.public_multikey, "message_b64": b64(msg), "signature": k.sign(msg) + "=", "valid": False,
             "reason": "padded base64url is not canonical"},
            {"multikey": k.public_multikey, "message_b64": b64(msg), "signature": "!" + k.sign(msg)[1:],
             "valid": False, "reason": "character outside the base64url alphabet"},
            {"multikey": k.public_multikey, "message_b64": b64(msg), "signature": k.sign(msg)[:-1], "valid": False,
             "reason": "truncated signature"},
        ],
    }


# --------------------------------------------------------------------------- #
# key event logs
# --------------------------------------------------------------------------- #


def _sign(body: dict, key: KeyPair) -> str:
    return key.sign(canonical_json(body))


def _reinception(event: dict, key: KeyPair) -> dict:
    """Recompute the DID and signature after editing an inception body, so only the edit is wrong."""
    body = {k: v for k, v in event["body"].items() if k != "did"}
    body["did"] = "did:agent:" + digest(canonical_json(body))[1:]
    return {**event, "body": body, "signer": body["did"], "sig": _sign(body, key)}


def kel() -> dict:
    trust = lambda d, k: True  # noqa: E731
    cases: list = []

    def expect_state(state) -> dict:
        return {"did": state.did, "seq": state.seq, "active": state.active, "key": state.key,
                "kid": state.key_id if state.active else None, "next": state.next, "controller": state.controller,
                "last_digest": state.last_digest}

    def valid(name: str, log: list, note: str) -> None:
        st = verify_log(copy.deepcopy(log), trust)
        cases.append({"name": name, "description": note, "log": log, "valid": True, "state": expect_state(st)})

    def invalid(name: str, log: list, reason: str) -> None:
        expect_raises(lambda: verify_log(copy.deepcopy(log), trust), InvalidEvent, name)
        cases.append({"name": name, "description": reason, "log": log, "valid": False})

    k0, k1, k2, k3 = kp("agent-0"), kp("agent-1"), kp("agent-2"), kp("agent-3")
    inc = make_inception(k0, k1, meta={"name": "researcher"})
    st0 = verify_inception(inc, trust)
    rot1 = make_rotation(st0, k1, k2)
    st1 = identity_mod.apply_event(st0, rot1, trust)
    rot2 = make_rotation(st1, k2, k3)

    valid("inception", [inc], "a single inception event")
    valid("two_rotations", [inc, rot1, rot2], "inception followed by two rotations to the pre-committed keys")
    valid("self_deactivation", [inc, rot1, make_deactivation(st1, st1.did, k2)],
          "deactivated with the pre-committed recovery key")

    ck0, ck1 = kp("controller-0"), kp("controller-1")
    cinc = make_inception(ck0, ck1, meta={"name": "owner"})
    cst = verify_inception(cinc, trust)
    winc = make_inception(kp("worker-0"), kp("worker-1"), controller=cst.did, controller_key=ck0, meta={"name": "worker"})
    wst = verify_inception(winc, trust)
    valid("controlled_inception", [winc], "inception countersigned by a controller")
    valid("controller_deactivation", [winc, make_deactivation(wst, cst.did, ck0)],
          "deactivated by its controller's key")
    cases.append({"name": "controller_log", "description": "the controller's own log (for verifiers that bind "
                  "controller keys)", "log": [cinc], "valid": True, "state": expect_state(cst)})

    # --- invalid ---
    t = copy.deepcopy(inc)
    t["body"]["meta"]["name"] = "evil"
    invalid("did_mismatch", [t], "body edited after the DID was derived")

    t = copy.deepcopy(inc)
    t["sig"] = _sign(t["body"], k1)
    invalid("inception_bad_signature", [t], "inception signed with a key other than body.key")

    t = copy.deepcopy(inc)
    t["body"]["extra"] = "x"
    invalid("inception_unknown_field", [_reinception(t, k0)], "unknown body field (re-derived DID and re-signed)")

    t = copy.deepcopy(inc)
    t["body"]["ts"] = "2027-01-15 08:00:00"
    invalid("inception_bad_ts", [_reinception(t, k0)], "ts not in YYYY-MM-DDThh:mm:ssZ form")

    t = copy.deepcopy(inc)
    t["body"]["next"] = "znotadigest"
    invalid("inception_bad_next", [_reinception(t, k0)], "next is not a well-formed digest")

    t = copy.deepcopy(inc)
    t["body"]["meta"] = {"weight": 1.5}
    invalid("inception_float", [t], "floats are not allowed in signed payloads")

    t = copy.deepcopy(inc)
    deep: dict = {}
    cur = deep
    for _ in range(17):
        cur["a"] = {}
        cur = cur["a"]
    t["body"]["meta"] = deep
    invalid("inception_meta_too_deep", [_reinception(t, k0)], "meta nested more than 16 levels")

    t = copy.deepcopy(inc)
    t["sig"] += "="
    invalid("inception_noncanonical_sig", [t], "padded signature encoding")

    t = copy.deepcopy(winc)
    del t["controller_proof"]
    invalid("missing_controller_proof", [t], "controller named but no countersignature")

    t = copy.deepcopy(inc)
    t["controller_proof"] = {"key": k0.public_multikey, "sig": _sign(inc["body"], k0)}
    invalid("proof_without_controller", [t], "controller_proof on an inception with no controller")

    t = copy.deepcopy(inc)
    t["extra"] = 1
    invalid("unknown_envelope_field", [t], "unknown envelope field")

    invalid("stolen_current_key_rotation", [inc, make_rotation(st0, k0, kp("attacker"))],
            "rotation signed by the current key instead of the pre-committed one")

    r = copy.deepcopy(rot1)
    r["body"]["prev"] = digest(b"elsewhere")
    r["sig"] = _sign(r["body"], k1)
    invalid("rotation_bad_prev", [inc, r], "prev does not chain to the previous event")

    r = copy.deepcopy(rot1)
    r["body"]["seq"] = 2
    r["sig"] = _sign(r["body"], k1)
    invalid("rotation_bad_seq", [inc, r], "seq skips a number")

    r = copy.deepcopy(rot1)
    r["body"]["next"] = key_commitment(k1.public_multikey)
    r["sig"] = _sign(r["body"], k1)
    invalid("rotation_next_equals_key", [inc, r], "next commits to the key being revealed")

    invalid("events_out_of_order", [inc, rot2, rot1], "events reordered")
    invalid("after_deactivation", [inc, make_deactivation(st0, st0.did, k1), rot1], "event after deactivation")
    invalid("empty_log", [], "empty log")
    invalid("starts_with_rotation", [rot1], "first event is not an inception")

    stranger = kp("stranger")
    invalid("deactivation_by_stranger", [inc, make_deactivation(st0, "did:agent:" + "1" * 45, stranger)],
            "deactivation signed by someone who is neither the agent's recovery key nor its controller")
    d = make_deactivation(st0, st0.did, k0)
    invalid("self_deactivation_with_current_key", [inc, d], "self-deactivation must use the recovery key")

    t = copy.deepcopy(inc)
    t["body"]["next"] = key_commitment(k0.public_multikey)
    invalid("inception_next_equals_key", [_reinception(t, k0)], "inception commits to its own current key")

    t = copy.deepcopy(inc)
    t["body"]["meta"] = {"n": 2 ** 53}
    invalid("inception_unsafe_int", [_reinception(t, k0)], "integer above 2**53-1 in a signed payload")

    t = copy.deepcopy(inc)
    deep2: list = []
    cur2 = deep2
    for _ in range(30):
        cur2.append([])
        cur2 = cur2[0]
    t = copy.deepcopy(inc)
    t["body"]["meta"] = {"x": deep2}
    invalid("event_too_deep", [t], "event nested deeper than 24 levels (rejected before hashing)")

    # A deactivation that names the controller and is signed by a key the controller never had.
    # Signature-only verifiers accept it; verifiers that bind controller keys (protocol §2.4) must not.
    forged = make_deactivation(wst, cst.did, stranger)
    cases.append({"name": "controller_deactivation_unbound_key",
                  "description": "deactivation claiming to be from the controller, signed by a key that is not in "
                                 "the controller's log; invalid once controller keys are bound to controller_log",
                  "log": [winc, forged], "valid": True, "valid_with_controller_binding": False,
                  "controller_log": "controller_log", "state": expect_state(verify_log(copy.deepcopy([winc, forged]),
                                                                                      trust))})
    bound = {cst.did: {k for _, k in cst.history}}
    expect_raises(lambda: verify_log(copy.deepcopy([winc, forged]), lambda d, k: k in bound.get(d, set())),
                  InvalidEvent, "controller_deactivation_unbound_key")
    return {"cases": cases}


# --------------------------------------------------------------------------- #
# request authentication
# --------------------------------------------------------------------------- #


def requests() -> dict:
    agent0, agent1, agent2 = kp("req-0"), kp("req-1"), kp("req-2")
    inc = make_inception(agent0, agent1, meta={"name": "caller"})
    st0 = verify_inception(inc, lambda d, k: True)
    rot = make_rotation(st0, agent1, agent2)
    st1 = identity_mod.apply_event(st0, rot, lambda d, k: True)
    did, kid, key = st1.did, st1.key_id, agent1  # current key is key-1 (agent1)
    other = kp("req-other")
    oinc = make_inception(other, kp("req-other-next"))
    odid = verify_inception(oinc, lambda d, k: True).did
    keys = {did: {"key": st1.key, "kid": kid}, odid: {"key": other.public_multikey, "kid": odid + "#key-0"}}
    audiences = ["api.example.com", "localhost:8000"]
    cases: list = []

    def run(c: dict) -> list:
        nonce_store: dict = {}

        class Nonces:
            ttl = 10_000

            def check_and_store(self, d, n):
                if (d, n) in nonce_store:
                    return False
                nonce_store[(d, n)] = 1
                return True

        v = RequestVerifier(lambda d: (keys[d]["key"], keys[d]["kid"]) if d in keys else None,
                            audiences=set(audiences), max_skew=120, nonce_cache=Nonces())
        out = []
        with mock.patch("agentauth.httpsig.time.time", lambda: c["now"]):
            for _ in range(c.get("repeat", 1)):
                try:
                    a = v.verify(authorization=c["authorization"], method=c["method"], path=c["path"],
                                 body=base64.b64decode(c["body_b64"]), grants=c["grants"])
                    out.append({"valid": True, "did": a.did, "kid": a.kid})
                except AuthError as e:
                    out.append({"valid": False, "status": e.status})
        return out

    def case(name: str, description: str, *, url="https://api.example.com/v1/search?q=agents", method="POST",
             body=b'{"q":"agents"}', grants="", ts=NOW, nonce="vector-nonce-0000000001", signer=key,
             s_did=None, s_kid=None, verify_method=None, verify_path=None, verify_body=None, verify_grants=None,
             now=NOW, mutate=None, repeat=1, expect: list) -> None:
        h = sign_request(did=s_did or did, kid=s_kid or kid, key=signer, method=method, url=url, body=body, ts=ts,
                         nonce=nonce, grants=grants)
        if mutate:
            h = mutate(h)
        from urllib.parse import urlsplit

        parts = urlsplit(url)
        path = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        c = {"name": name, "description": description, "now": now, "authorization": h,
             "method": verify_method or method, "path": verify_path or path,
             "body_b64": b64(body if verify_body is None else verify_body),
             "grants": grants if verify_grants is None else verify_grants, "repeat": repeat}
        got = run(c)
        want = [{"valid": True, "did": s_did or did, "kid": s_kid or kid} if e == "ok" else {"valid": False, "status": e}
                for e in expect]
        if got != want:
            raise SystemExit(f"generator bug: request vector {name!r}: python gave {got}, intended {want}")
        c["expect"] = want
        cases.append(c)

    case("valid_post", "a correctly signed POST", expect=["ok"])
    case("valid_get_no_body", "GET with an empty body", method="GET", body=b"", url="https://api.example.com/v1/me",
         expect=["ok"])
    case("valid_percent_encoded_path", "the raw (still percent-encoded) path is what's signed",
         method="GET", body=b"", url="https://api.example.com/files/q3%20report.pdf?v=a%2Fb", expect=["ok"])
    case("valid_with_port", "audience with an explicit port", url="http://localhost:8000/x", method="GET", body=b"",
         expect=["ok"])
    case("valid_with_grant_header", "the AgentGrant header value is covered", grants="eyJ2IjoiZ3JhbnQifQ.c2ln",
         expect=["ok"])
    case("valid_method_case", "the verifier upper-cases the method", verify_method="post", expect=["ok"])
    case("replay", "the same signed request twice: the second is a replay", repeat=2, expect=["ok", 401])
    case("ts_edge_of_window", "exactly max_skew (120 s) old is still accepted", ts=NOW - 120, expect=["ok"])

    case("wrong_audience", "signed for a host the verifier doesn't serve", url="https://other.example.org/v1/search",
         expect=[401])
    case("stale_timestamp", "121 s old", ts=NOW - 121, expect=[401])
    case("future_timestamp", "121 s in the future", ts=NOW + 121, expect=[401])
    case("noncanonical_timestamp", "ts with a leading +",
         mutate=lambda h: h.replace(f'ts="{NOW}"', f'ts="+{NOW}"'), expect=[401])
    case("short_nonce", "nonce under 16 characters", nonce="tooshort", expect=[401])
    case("duplicate_parameter", "a second did parameter appended",
         mutate=lambda h: h + f',did="{odid}"', expect=[401])
    case("missing_parameter", "no nonce parameter",
         mutate=lambda h: ",".join(p for p in h.split(",") if not p.startswith("nonce=")), expect=[401])
    case("wrong_scheme", "Bearer instead of AgentSig", mutate=lambda h: "Bearer " + h.split(" ", 1)[1], expect=[401])
    case("kid_of_other_did", "kid that belongs to a different DID", s_kid=odid + "#key-0", expect=[401])
    case("old_key", "signed with key-0 after the agent rotated to key-1", signer=agent0, s_kid=did + "#key-0",
         expect=[401])
    case("unknown_agent", "DID the resolver doesn't know", s_did="did:agent:" + "1" * 46,
         s_kid="did:agent:" + "1" * 46 + "#key-0", expect=[401])
    case("different_path", "verifier sees a different path", verify_path="/v1/admin", expect=[401])
    case("different_query", "verifier sees a different query", verify_path="/v1/search?q=other", expect=[401])
    case("different_method", "verifier sees a different method", verify_method="DELETE", expect=[401])
    case("body_tampered", "body changed after signing", verify_body=b'{"q":"evil"}', expect=[401])
    case("grant_header_swapped", "a different AgentGrant header than the one signed", grants="a.b",
         verify_grants="c.d", expect=[401])
    case("signature_padded", "padded signature encoding", mutate=lambda h: h[:-1] + '="', expect=[401])
    case("wrong_key", "signed by another agent's key", signer=other, expect=[401])

    sstr = signing_string("post", "API.Example.com", "/v1/search?q=agents", str(NOW), "vector-nonce-0000000001",
                          b'{"q":"agents"}', "g")
    return {
        "audiences": audiences,
        "max_skew": 120,
        "keys": keys,
        "signing_string": [{
            "method": "post", "audience": "API.Example.com", "path": "/v1/search?q=agents", "ts": str(NOW),
            "nonce": "vector-nonce-0000000001", "body_b64": b64(b'{"q":"agents"}'), "grants": "g",
            "signing_string": sstr.decode(),
        }],
        "cases": cases,
    }


# --------------------------------------------------------------------------- #
# grant chains
# --------------------------------------------------------------------------- #


def grants() -> dict:
    trust = lambda d, k: True  # noqa: E731

    def ident(label):
        cur, nxt = kp(f"grant-{label}-0"), kp(f"grant-{label}-1")
        st = verify_inception(make_inception(cur, nxt, meta={"name": label}), trust)
        return st, cur, nxt

    H, hk, hnext = ident("human")
    A, ak, _ = ident("agent")
    S, sk, _ = ident("sub")
    X, xk, _ = ident("stranger")
    R, rk0, rk1 = ident("rotated-issuer")
    r_rot = make_rotation(R, rk1, kp("grant-rotated-issuer-2"))
    R1 = identity_mod.apply_event(R, r_rot, trust)

    keys = {s.did: {"key": s.key, "kid": s.key_id} for s in (H, A, S, X)}
    keys[R1.did] = {"key": R1.key, "kid": R1.key_id}
    policy = {H.did: ["tools.*", "pay.*", "files.*"], R1.did: ["tools.*"]}
    aud = "tools.example.com"
    cases: list = []

    def verify(header, requester, *, now=NOW, audience=aud, revoked=()):
        gv = GrantVerifier(lambda d: (keys[d]["key"], keys[d]["kid"]) if d in keys else None,
                           trust_principals(policy), revoked=lambda pairs: {p for p in pairs if list(p) in [list(r) for r in revoked]})
        return gv.verify(header, requester=requester, audience=audience, now=now)

    def case(name, description, header, requester, *, now=NOW, audience=aud, revoked=(), status=None):
        c = {"name": name, "description": description, "header": header, "requester": requester, "now": now,
             "audience": audience, "revoked": [list(r) for r in revoked]}
        if status is None:
            a = verify(header, requester, now=now, audience=audience, revoked=revoked)
            c["expect"] = {"valid": True, "principal": a.principal, "via": a.via, "scopes": a.scopes,
                           "grant_ids": a.grant_ids, "leaf_limits": a.limits}
        else:
            e = expect_raises(lambda: verify(header, requester, now=now, audience=audience, revoked=revoked),
                              GrantError, name)
            if e.status != status:
                raise SystemExit(f"generator bug: grant vector {name!r} gave status {e.status}, intended {status}")
            c["expect"] = {"valid": False, "status": status}
        cases.append(c)

    def iss(issuer_st, issuer_key, subject, scopes, *, parent=None, depth=0, ttl=900, limits=None, audiences=(aud,),
            now=NOW):
        return grants_mod.issue(issuer_did=issuer_st.did, issuer_kid=issuer_st.key_id, issuer_key=issuer_key,
                                subject=subject, scopes=scopes, audiences=list(audiences), ttl=ttl, depth=depth,
                                parent=parent, limits=limits, now=now)

    root = iss(H, hk, A.did, ["tools.*", "pay.*"], depth=1,
               limits=Limits.build(resources=["repo:acme/*"], per_call=500, total=5000, rate=(10, 60), uses=100))
    child = iss(A, ak, S.did, ["tools.search"], parent=root,
                limits=Limits.build(resources=["repo:acme/website"], total=1000, uses=20))
    simple = iss(H, hk, A.did, ["tools.search"])

    case("root_grant", "a principal's grant used by its subject", simple.encode(), A.did)
    case("delegated_chain", "two links with narrowing limits", child.encode(), S.did)
    case("wildcard_audience", "audience '*' covers any service",
         iss(H, hk, A.did, ["tools.search"], audiences=("*",)).encode(), A.did)
    case("audience_case_insensitive", "audiences compare case-insensitively", simple.encode(), A.did,
         audience="Tools.Example.COM")
    case("clock_skew_grace", "still valid 59 s after exp (60 s grace)", simple.encode(), A.did,
         now=simple.leaf.exp + 59)

    case("no_grant", "empty header", "", A.did, status=401)
    case("untrusted_root", "root issuer not in the policy", iss(X, xk, A.did, ["tools.search"]).encode(), A.did,
         status=403)
    case("root_exceeds_policy", "principal grants a scope the policy doesn't allow it",
         iss(H, hk, A.did, ["admin.*"]).encode(), A.did, status=403)
    case("wrong_requester", "grant used by someone other than its subject", simple.encode(), X.did, status=403)
    case("wrong_audience", "grant for a different service", simple.encode(), A.did, audience="other.example.com",
         status=403)
    case("expired", "61 s past exp", simple.encode(), A.did, now=simple.leaf.exp + 61, status=403)
    case("not_yet_valid", "61 s before nbf", simple.encode(), A.did, now=simple.leaf.nbf - 61, status=403)
    case("revoked_root", "root revoked by its issuer", child.encode(), S.did,
         revoked=[(H.did, root.leaf.id)], status=403)
    case("revoked_leaf", "leaf revoked by its issuer", child.encode(), S.did, revoked=[(A.did, child.leaf.id)],
         status=403)
    case("stale_issuer_key", "issued under key-0, issuer has rotated to key-1",
         iss(R, rk0, A.did, ["tools.search"]).encode(), A.did, status=403)

    def forged_link(base: GrantChain, issuer_st, issuer_key, **overrides) -> GrantChain:
        p = base.leaf
        body = {"v": "agentauth-grant/1", "id": "forged-link-0000000001", "iss": issuer_st.did,
                "kid": issuer_st.key_id, "sub": S.did, "scope": ["tools.search"], "aud": [aud], "nbf": p.nbf,
                "exp": p.exp, "depth": 0, "parent": p.id}
        if p.body.get("limits"):
            body["limits"] = p.body["limits"]
        body.update(overrides)
        body = {k: v for k, v in body.items() if v is not ...}
        return GrantChain(base.links + [Grant(body, issuer_key.sign(canonical_json(body)))])

    case("widened_scope", "child claims a scope its parent lacks",
         forged_link(root, A, ak, scope=["admin.wipe"]).encode(), S.did, status=403)
    case("widened_audience", "child adds an audience",
         forged_link(root, A, ak, aud=[aud, "evil.example.com"]).encode(), S.did, status=403)
    case("outlives_parent", "child exp after parent exp",
         forged_link(root, A, ak, exp=root.leaf.exp + 10).encode(), S.did, status=403)
    case("depth_exceeded", "parent depth 0 but a child exists",
         forged_link(simple, A, ak).encode(), S.did, status=403)
    case("dropped_limits", "child omits the parent's limits", forged_link(root, A, ak, limits=...).encode(), S.did,
         status=403)
    case("loosened_budget", "child raises spend.total above the parent's",
         forged_link(root, A, ak, limits={**root.leaf.body["limits"],
                                          "spend": {"unit": "USD-cents", "per_call": 500, "total": 9999}}).encode(),
         S.did, status=403)
    case("unknown_field", "a field verifiers don't understand",
         forged_link(root, A, ak, constraints={"geo": "EU"}).encode(), S.did, status=403)
    case("unknown_limit", "an unknown limit kind",
         forged_link(root, A, ak, limits={**root.leaf.body["limits"], "geo": "EU"}).encode(), S.did, status=403)
    case("wrong_parent_id", "child references a different parent",
         forged_link(root, A, ak, parent="not-the-parent-00000").encode(), S.did, status=403)
    case("issuer_not_parent_subject", "child issued by someone other than the parent's subject",
         forged_link(root, X, xk).encode(), S.did, status=403)
    case("self_issued", "a link issued to its own issuer",
         forged_link(root, A, ak, sub=A.did).encode(), A.did, status=403)

    t = simple.links[0]
    tb = dict(t.body)
    tb["scope"] = ["tools.*"]
    case("tampered_body", "scope edited without re-signing", GrantChain([Grant(tb, t.sig)]).encode(), A.did,
         status=403)
    case("signature_padded", "padded signature encoding", simple.encode() + "=", A.did, status=403)
    case("missing_root", "chain without its root link", GrantChain(child.links[1:]).encode(), S.did, status=403)
    case("duplicate_link", "the same link twice", GrantChain(root.links + root.links).encode(), A.did, status=403)
    case("malformed", "not base64url JSON", "%%%.%%%", A.did, status=400)
    case("too_many_links", "nine links", ",".join([simple.encode()] * 9), A.did, status=403)
    case("float_in_body", "nbf as a float",
         b64u(json.dumps({**simple.leaf.body, "nbf": float(simple.leaf.nbf)}).encode()) + "." + simple.leaf.sig,
         A.did, status=400)
    case("noncanonical_payload", "payload JSON with whitespace (valid signature over the canonical form)",
         b64u(json.dumps(simple.leaf.body).encode()) + "." + simple.leaf.sig, A.did, status=400)
    dup = canonical_json(simple.leaf.body).decode()
    dup = dup[:-1] + ',"sub":' + json.dumps(X.did) + "}"
    case("duplicate_key", "payload with a second 'sub' key", b64u(dup.encode()) + "." + simple.leaf.sig, A.did,
         status=400)

    def raw_root(**overrides) -> str:
        body = dict(simple.leaf.body)
        body.update(overrides)
        body = {k: v for k, v in body.items() if v is not ...}
        return GrantChain([Grant(body, hk.sign(canonical_json(body)))]).encode()

    case("unsorted_audience", "aud not in sorted order (signed)", raw_root(aud=[aud, "a.example.com"]), A.did,
         status=403)
    case("uppercase_audience", "aud not lower-cased (signed)", raw_root(aud=["Tools.Example.com"]), A.did,
         status=403)
    case("unsorted_scope", "scope not in sorted order (signed)", raw_root(scope=["tools.search", "pay.x"]), A.did,
         status=403)
    case("non_ascii_audience", "aud with a non-ASCII character (signed)", raw_root(aud=["tools.exampİe.com"]),
         A.did, status=403)
    case("stateful_wildcard_audience", "a use limit on audience '*' (signed)",
         raw_root(aud=["*"], limits={"uses": 5}), A.did, status=403)

    scope_pairs = [("*", "a.b"), ("tools.*", "tools.search"), ("tools.*", "tools.web.fetch"), ("tools.*", "tools.*"),
                   ("tools.*", "tools"), ("tools.*", "toolsX.search"), ("tools.search", "tools.search"),
                   ("tools.search", "tools.*"), ("tools.search", "*")]
    aud_pairs = [(["*"], ["x.example"]), (["a.example"], ["A.EXAMPLE"]), (["a.example"], ["b.example"]),
                 (["a.example", "b.example"], ["b.example"])]
    return {
        "keys": keys,
        "root_policy": policy,
        "cases": cases,
        "scope_covers": [{"parent": p, "child": c, "covers": scope_covers(p, c)} for p, c in scope_pairs],
        "audience_covers": [{"parents": p, "children": c, "covers": audience_covers(p, c)} for p, c in aud_pairs],
    }


# --------------------------------------------------------------------------- #
# limits
# --------------------------------------------------------------------------- #


def limits() -> dict:
    def violation(parent: dict, child: dict) -> bool:
        return Limits.from_dict(parent).narrowing_violation(Limits.from_dict(child)) is not None

    narrowing = [
        ({"resources": ["/reports/*"]}, {"resources": ["/reports/2026/*"]}),
        ({"resources": ["/reports/*"]}, {"resources": ["/secrets/*"]}),
        ({"resources": ["/reports/*"]}, {}),
        ({"resources": ["/reports/q3.pdf"]}, {"resources": ["/reports/*"]}),
        ({"spend": {"unit": "USD-cents", "total": 100}}, {"spend": {"unit": "USD-cents", "total": 50}}),
        ({"spend": {"unit": "USD-cents", "total": 100}}, {"spend": {"unit": "USD-cents", "total": 150}}),
        ({"spend": {"unit": "USD-cents", "total": 100}}, {"spend": {"unit": "EUR-cents", "total": 50}}),
        ({"spend": {"unit": "USD-cents", "per_call": 10}}, {"spend": {"unit": "USD-cents", "total": 5}}),
        ({"rate": {"count": 10, "per": 60}}, {"rate": {"count": 100, "per": 3600}}),
        ({"rate": {"count": 10, "per": 60}}, {"rate": {"count": 5, "per": 10}}),
        ({"rate": {"count": 10, "per": 60}}, {}),
        ({"uses": 10}, {"uses": 10}),
        ({"uses": 10}, {"uses": 11}),
        ({}, {"uses": 3, "resources": ["x"]}),
        # U+FEFF is not whitespace to Python's str.isspace() (it is to JavaScript's \s): a valid pattern.
        ({"resources": ["/a\ufeff/*"]}, {"resources": ["/a\ufeff/b"]}),
        ({"resources": ["/\U0001f600/*", "/\uffff/*"]}, {"resources": ["/\uffff/x"]}),
    ]
    invalid = [
        {"resources": []}, {"resources": ["a*b"]}, {"resources": ["has space"]}, {"uses": 0}, {"uses": 2 ** 53},
        {"uses": True}, {"spend": {"unit": "u"}}, {"spend": {"unit": "a b", "total": 1}},
        {"spend": {"total": 1}}, {"rate": {"count": 1, "per": 86401}}, {"rate": {"count": 1}}, {"geo": "EU"},
        {"resources": ["/a/\x7f*"]}, {"resources": ["/a/\x85"]}, {"spend": {"unit": "u\x9f", "total": 1}},
    ]
    for d in invalid:
        expect_raises(lambda d=d: Limits.from_dict(d), LimitError, f"limits {d}")

    calls = [
        ({"resources": ["/reports/*"]}, "/reports/q3.pdf", 0, None),
        ({"resources": ["/reports/*"]}, "/secrets/x", 0, None),
        ({"resources": ["/reports/*"]}, None, 0, None),
        ({"resources": ["/reports/*"]}, "/reports/../secrets/x", 0, None),
        ({"resources": ["/reports/*"]}, "/reports/./x", 0, None),
        ({"resources": ["/reports/*"]}, "/reports/x*", 0, None),
        ({"resources": ["/reports/*"]}, "/reports/x\x7f", 0, None),
        ({"resources": ["/reports/*"]}, "/reports/x\u0085", 0, None),
        ({"resources": ["/reports/*"]}, "/reports\\..\\secrets", 0, None),
        ({"spend": {"unit": "USD-cents", "per_call": 100}}, None, 100, "USD-cents"),
        ({"spend": {"unit": "USD-cents", "per_call": 100}}, None, 101, "USD-cents"),
        ({"spend": {"unit": "USD-cents", "per_call": 100}}, None, 50, "EUR-cents"),
        ({"spend": {"unit": "USD-cents", "total": 100}}, None, 0, None),
    ]
    call_cases = []
    for lim, res, amount, unit in calls:
        try:
            Limits.from_dict(lim).check_call(resource=res, amount=amount, unit=unit)
            out = {"valid": True}
        except LimitError as e:
            out = {"valid": False, "status": e.status}
        call_cases.append({"limits": lim, "resource": res, "amount": amount, "unit": unit, "expect": out})

    patterns = [("/reports/*", "/reports/q3.pdf"), ("/reports/*", "/reports"), ("/reports/q3.pdf", "/reports/q3.pdf"),
                ("/reports/q3.pdf", "/reports/q4.pdf"), ("*", "anything")]
    covers = [("/reports/*", "/reports/2026/*"), ("/reports/2026/*", "/reports/*"), ("/a/*", "/a/b"),
              ("/a/b", "/a/*")]
    return {
        "narrowing": [{"parent": p, "child": c, "violation": violation(p, c)} for p, c in narrowing],
        "invalid": [{"limits": d} for d in invalid],
        "check_call": call_cases,
        "pattern_matches": [{"pattern": p, "resource": r, "matches": pattern_matches(p, r)} for p, r in patterns],
        "pattern_covers": [{"parent": p, "child": c, "covers": pattern_covers(p, c)} for p, c in covers],
    }


# --------------------------------------------------------------------------- #
# revocations
# --------------------------------------------------------------------------- #


def revocations() -> dict:
    k = kp("revoker-0")
    inc = make_inception(k, kp("revoker-1"))
    st = verify_inception(inc, lambda d, kk: True)
    good = make_revocation(issuer_did=st.did, issuer_key=k, grant_id="grant-0001")
    verify_revocation(good, k.public_multikey)
    cases = [{"name": "valid", "event": good, "issuer_key": k.public_multikey, "valid": True}]

    def bad(name, mutate, key=k.public_multikey):
        e = copy.deepcopy(good)
        mutate(e)
        expect_raises(lambda: verify_revocation(e, key), GrantError, name)
        cases.append({"name": name, "event": e, "issuer_key": key, "valid": False})

    bad("wrong_key", lambda e: None, key=kp("someone-else").public_multikey)
    bad("extra_field", lambda e: e["body"].update(reason="oops"))
    bad("ts_float", lambda e: e["body"].update(ts=1.5))
    bad("ts_bool", lambda e: e["body"].update(ts=True))
    bad("empty_grant_id", lambda e: e["body"].update(grant=""))
    bad("bad_issuer", lambda e: e["body"].update(iss="not-a-did"))
    bad("padded_signature", lambda e: e.update(sig=e["sig"] + "="))
    bad("extra_envelope_field", lambda e: e.update(note=1))
    # For registry clients: the issuer's log (to check proofs against its key history), and a
    # well-formed revocation of the same grant signed by a key the issuer never held.
    forged = {"body": dict(good["body"]), "sig": kp("someone-else").sign(canonical_json(good["body"]))}
    return {"cases": cases, "issuer_log": [inc], "forged_proof": forged}


# --------------------------------------------------------------------------- #


def build() -> dict:
    with Pinned():
        return {
            "primitives.json": primitives(),
            "kel.json": kel(),
            "requests.json": requests(),
            "grants.json": grants(),
            "limits.json": limits(),
            "revocations.json": revocations(),
        }


def render(data: dict, name: str) -> str:
    doc = {"format": FORMAT, "generated_by": "scripts/generate_test_vectors.py", "file": name, **data}
    return json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if committed vectors differ from freshly generated ones")
    args = ap.parse_args()
    files = {name: render(data, name) for name, data in build().items()}
    stale = []
    for name, text in files.items():
        path = OUT / name
        if args.check:
            if not path.exists() or path.read_text() != text:
                stale.append(name)
        else:
            OUT.mkdir(exist_ok=True)
            path.write_text(text)
    if args.check:
        if stale:
            sys.exit(f"stale test vectors: {', '.join(stale)}; run python scripts/generate_test_vectors.py")
        print("test vectors are up to date")
    else:
        print(f"wrote {len(files)} files to {OUT}")


if __name__ == "__main__":
    main()

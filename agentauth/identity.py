"""Self-certifying agent identifiers backed by a verifiable key event log.

Model (a deliberately small cousin of KERI):

* An agent's DID is derived from the digest of its *inception event*, so the
  identifier is bound to the key material it was born with. No registry can
  mint or reassign it.
* Every event is signed and hash-chained to the previous one. Anyone holding
  the log can replay it and compute the current key without trusting the
  server that handed it over.
* **Pre-rotation**: each establishment event commits to the digest of the
  *next* public key. A rotation must reveal a key matching that commitment and
  be signed by it. Stealing the current signing key is therefore not enough
  to take over an identity.
* An optional **controller** (e.g. the human or org that owns the agent, itself
  a DID) may deactivate the agent — the kill switch.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .crypto import Signer, canonical_json, digest, is_digest, key_commitment, multikey_to_public_key, verify

VERSION = "agentauth/1"
DID_PREFIX = "did:agent:"

INCEPTION = "inception"
ROTATION = "rotation"
DEACTIVATION = "deactivation"

# Given (controller DID, multikey) decide whether that key may act for the
# controller. The registry checks against the controller's *current* key;
# an auditor replaying an old log may accept any key the controller has held.
ControllerKeyCheck = Callable[[str, str], bool]


def trust_embedded_controller_keys(did: str, key: str) -> bool:
    """Checks signatures only, not that the key belonged to the controller."""
    return True


class InvalidEvent(ValueError):
    """Raised when an event or log fails verification."""


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _did_from_inception(body: dict) -> str:
    unsigned = {k: v for k, v in body.items() if k != "did"}
    return DID_PREFIX + digest(canonical_json(unsigned))[1:]  # drop multibase 'z'


# did:agent:<base58btc of a 34-byte sha2-256 multihash> is 45-46 characters after the prefix.
_DID_RE = re.compile(r"\Adid:agent:[1-9A-HJ-NP-Za-km-z]{40,60}\Z")
_TS_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")

# Exact field sets. Unknown fields are rejected so that two implementations can
# never disagree about what an event means.
_INCEPTION_FIELDS = {"v", "type", "seq", "prev", "key", "next", "controller", "meta", "ts", "did"}
_UPDATE_FIELDS = {"v", "type", "did", "seq", "prev", "key", "next", "ts"}
_ENVELOPE_FIELDS = {"body", "signer", "sig", "controller_proof"}


def is_agent_did(value: Any) -> bool:
    return isinstance(value, str) and _DID_RE.match(value) is not None


def event_digest(event: dict) -> str:
    return digest(canonical_json(event["body"]))


def _signed(body: dict, signer_did: str, key: Signer) -> dict:
    return {"body": body, "signer": signer_did, "sig": key.sign(canonical_json(body))}


# --------------------------------------------------------------------------- #
# Event construction (client side)
# --------------------------------------------------------------------------- #


def make_inception(
    current: Signer,
    next_key: Signer,
    *,
    controller: Optional[str] = None,
    controller_key: Optional[Signer] = None,
    meta: Optional[dict] = None,
) -> dict:
    """Create a self-signed inception event.

    If `controller` is given, `controller_key` (the controller's current key)
    countersigns the event so the registry knows the controller consented.
    """
    body: dict[str, Any] = {
        "v": VERSION,
        "type": INCEPTION,
        "seq": 0,
        "prev": None,
        "key": current.public_multikey,
        "next": key_commitment(next_key.public_multikey),
        "controller": controller,
        "meta": meta or {},
        "ts": now_iso(),
    }
    body["did"] = _did_from_inception(body)
    event = _signed(body, body["did"], current)
    if controller:
        if controller_key is None:
            raise ValueError("controller_key is required to countersign when a controller is set")
        event["controller_proof"] = {
            "key": controller_key.public_multikey,
            "sig": controller_key.sign(canonical_json(body)),
        }
    return event


def make_rotation(state: IdentityState, new_current: Signer, new_next: Signer) -> dict:
    """Rotate to the pre-committed key (`new_current`) and commit to `new_next`."""
    body = {
        "v": VERSION,
        "type": ROTATION,
        "did": state.did,
        "seq": state.seq + 1,
        "prev": state.last_digest,
        "key": new_current.public_multikey,
        "next": key_commitment(new_next.public_multikey),
        "ts": now_iso(),
    }
    return _signed(body, state.did, new_current)


def make_deactivation(state: IdentityState, signer_did: str, signer_key: Signer) -> dict:
    """Deactivate an identity.

    Signed either by the agent's pre-committed *next* key (proving the holder
    of the recovery key wants it dead) or by the controller's current key.
    """
    body = {
        "v": VERSION,
        "type": DEACTIVATION,
        "did": state.did,
        "seq": state.seq + 1,
        "prev": state.last_digest,
        "key": signer_key.public_multikey,
        "next": None,
        "ts": now_iso(),
    }
    return _signed(body, signer_did, signer_key)


# --------------------------------------------------------------------------- #
# Verification (anyone can run this)
# --------------------------------------------------------------------------- #


@dataclass
class IdentityState:
    did: str
    seq: int
    key: Optional[str]  # current signing key; None once deactivated
    next: Optional[str]  # commitment to next key
    controller: Optional[str]
    meta: dict
    active: bool
    created: str
    updated: str
    last_digest: str
    key_seq: int = 0  # seq of the event that established the current key
    history: list = field(default_factory=list)  # [(seq, key)] of all past keys

    @property
    def key_id(self) -> str:
        return f"{self.did}#key-{self.key_seq}"

    def did_document(self) -> dict:
        doc: dict[str, Any] = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1",
            ],
            "id": self.did,
            "controller": [self.did] + ([self.controller] if self.controller else []),
            "verificationMethod": [],
            "authentication": [],
            "assertionMethod": [],
        }
        if self.active and self.key:
            vm = {
                "id": self.key_id,
                "type": "Multikey",
                "controller": self.did,
                "publicKeyMultibase": self.key,
            }
            doc["verificationMethod"].append(vm)
            doc["authentication"].append(vm["id"])
            doc["assertionMethod"].append(vm["id"])
        if self.meta:
            doc["agent"] = copy.deepcopy(self.meta)
        return doc

    def resolution_result(self) -> dict:
        return {
            "didDocument": self.did_document(),
            "didDocumentMetadata": {
                "created": self.created,
                "updated": self.updated,
                "deactivated": not self.active,
                "versionId": str(self.seq),
                "nextKeyCommitment": self.next,
            },
        }


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise InvalidEvent(msg)


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _check_envelope(event: Any) -> dict:
    _require(isinstance(event, dict), "event must be an object")
    _require(not (set(event) - _ENVELOPE_FIELDS), "event envelope has unknown fields")
    _require(isinstance(event.get("signer"), str), "signer must be a string")
    _require(isinstance(event.get("sig"), str), "sig must be a string")
    body = event.get("body")
    _require(isinstance(body, dict), "event body must be an object")
    return body


def _check_common(body: dict, fields: set) -> None:
    _require(body.get("v") == VERSION, f"unsupported version {body.get('v')!r}")
    _require(set(body) == fields, "event body has missing or unknown fields")
    _require(_is_int(body.get("seq")) and body["seq"] >= 0, "seq must be a non-negative int")
    _require(isinstance(body.get("ts"), str) and _TS_RE.match(body["ts"]) is not None,
             "ts must be an RFC 3339 UTC timestamp (YYYY-MM-DDThh:mm:ssZ)")
    try:
        multikey_to_public_key(body.get("key"))  # type: ignore[arg-type]  # validated here
    except ValueError as e:
        raise InvalidEvent(f"bad key: {e}") from None


MAX_META_DEPTH = 16


def _depth(obj: Any, limit: int) -> int:
    """Nesting depth of a JSON value, computed iteratively (no recursion to exhaust)."""
    deepest, stack = 0, [(obj, 1)]
    while stack:
        o, d = stack.pop()
        if isinstance(o, (dict, list)):
            if d > limit:
                return d
            deepest = max(deepest, d)
            stack.extend((v, d + 1) for v in (o.values() if isinstance(o, dict) else o))
    return deepest


def _canonical(body: dict) -> bytes:
    try:
        return canonical_json(body)
    except (TypeError, ValueError) as e:
        raise InvalidEvent(f"event is not canonicalizable: {e}") from None


def verify_inception(event: dict, controller_check: ControllerKeyCheck) -> IdentityState:
    """Verify an inception event (including the controller's countersignature, if any)."""
    body = _check_envelope(event)
    sig = event["sig"]
    _require(body.get("type") == INCEPTION, "first event must be an inception")
    _check_common(body, _INCEPTION_FIELDS)
    _require(body["seq"] == 0 and body.get("prev") is None, "inception must have seq=0, prev=null")
    _require(is_digest(body.get("next")), "inception must commit to a next key (pre-rotation)")
    _require(isinstance(body.get("meta"), dict), "meta must be an object")
    _require(_depth(body["meta"], MAX_META_DEPTH) <= MAX_META_DEPTH, f"meta may nest at most {MAX_META_DEPTH} levels")
    msg = _canonical(body)
    _require(body.get("did") == _did_from_inception(body), "DID does not match inception digest")
    _require(event.get("signer") == body["did"], "inception must be self-signed")
    ctrl = body.get("controller")
    _require(ctrl is None or (is_agent_did(ctrl) and ctrl != body["did"]), "controller must be another agent DID")
    _require(verify(body["key"], msg, sig), "bad inception signature")
    if ctrl is not None:
        proof = event.get("controller_proof")
        if not isinstance(proof, dict) or set(proof) != {"key", "sig"}:
            raise InvalidEvent("missing or bad controller countersignature")
        _require(verify(proof["key"], msg, proof["sig"]), "missing or bad controller countersignature")
        _require(controller_check(ctrl, proof["key"]), "controller countersignature is not from a valid controller key")
    else:
        _require("controller_proof" not in event, "controller_proof without a controller")
    return IdentityState(
        did=body["did"],
        seq=0,
        key=body["key"],
        next=body["next"],
        controller=ctrl,
        meta=body["meta"],
        active=True,
        created=body["ts"],
        updated=body["ts"],
        last_digest=event_digest(event),
        key_seq=0,
        history=[(0, body["key"])],
    )


def apply_event(
    state: IdentityState,
    event: dict,
    controller_check: ControllerKeyCheck,
) -> IdentityState:
    """Validate `event` against `state` and return the new state (pure)."""
    body = _check_envelope(event)
    sig, signer = event["sig"], event["signer"]
    _require("controller_proof" not in event, "controller_proof is only valid on inception")
    _require(body.get("type") in (ROTATION, DEACTIVATION), f"unknown event type {body.get('type')!r}")
    _check_common(body, _UPDATE_FIELDS)
    _require(state.active, "identity is deactivated")
    _require(body.get("did") == state.did, "event is for a different DID")
    _require(body["seq"] == state.seq + 1, f"expected seq {state.seq + 1}, got {body['seq']}")
    _require(body.get("prev") == state.last_digest, "prev digest does not chain to the log")
    msg = _canonical(body)
    new = copy.deepcopy(state)
    new.seq, new.updated, new.last_digest = body["seq"], body["ts"], event_digest(event)

    if body["type"] == ROTATION:
        _require(signer == state.did, "rotation must be signed by the agent")
        _require(key_commitment(body["key"]) == state.next, "rotated key does not match pre-rotation commitment")
        _require(is_digest(body.get("next")), "rotation must commit to a new next key")
        _require(key_commitment(body["key"]) != body["next"], "next key must differ from current key")
        _require(verify(body["key"], msg, sig), "bad rotation signature")
        new.key, new.next, new.key_seq = body["key"], body["next"], body["seq"]
        new.history.append((body["seq"], body["key"]))
        return new

    if body["type"] == DEACTIVATION:
        _require(body.get("next") is None, "deactivation must not commit to a next key")
        if signer == state.did:
            _require(
                key_commitment(body["key"]) == state.next,
                "self-deactivation must be signed with the pre-committed recovery key",
            )
        else:
            _require(state.controller is not None and signer == state.controller, "only the agent or its controller may deactivate")
            _require(controller_check(signer, body["key"]), "deactivation not signed with a valid controller key")
        _require(verify(body["key"], msg, sig), "bad deactivation signature")
        new.active, new.key, new.next = False, None, None
        return new

    raise InvalidEvent(f"unknown event type {body.get('type')!r}")


def verify_log(
    events: list, controller_check: ControllerKeyCheck = trust_embedded_controller_keys
) -> IdentityState:
    """Replay a full key event log and return the resulting state.

    Self-certification (DID ↔ inception), hash chaining, pre-rotation and all
    signatures are always enforced. Supply `controller_check` to also bind
    controller signatures to the controller's own key history.
    """
    _require(isinstance(events, list) and len(events) > 0, "log is empty")
    state = verify_inception(events[0], controller_check)
    for ev in events[1:]:
        state = apply_event(state, ev, controller_check)
    return state

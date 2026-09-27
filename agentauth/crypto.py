"""Low-level primitives: Ed25519 keys, base58btc/multibase, canonical JSON, digests.

Everything here is deterministic and dependency-light so that any relying party
can re-implement verification in another language.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# --------------------------------------------------------------------------- #
# base58btc + multibase / multicodec
# --------------------------------------------------------------------------- #

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}

# multicodec varint prefixes
ED25519_PUB_CODEC = b"\xed\x01"
SHA2_256_MULTIHASH = b"\x12\x20"  # sha2-256, 32 bytes


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58_ALPHABET[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        if c not in _B58_INDEX:
            raise ValueError(f"invalid base58 character: {c!r}")
        n = n * 58 + _B58_INDEX[c]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


def multibase_encode(data: bytes) -> str:
    """Multibase base58btc ('z' prefix)."""
    return "z" + b58encode(data)


def multibase_decode(s: str) -> bytes:
    if not s.startswith("z"):
        raise ValueError("only base58btc multibase ('z') is supported")
    return b58decode(s[1:])


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# --------------------------------------------------------------------------- #
# Canonical JSON + digests
# --------------------------------------------------------------------------- #


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON (sorted keys, no whitespace, UTF-8).

    A pragmatic subset of RFC 8785 (JCS): we only ever sign dicts of strings,
    ints, bools, None and lists thereof, and floats are rejected outright.
    """

    def _check(o: Any) -> None:
        if isinstance(o, float):
            raise TypeError("floats are not allowed in signed payloads")
        if isinstance(o, dict):
            for k, v in o.items():
                if not isinstance(k, str):
                    raise TypeError("object keys must be strings")
                _check(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                _check(v)

    _check(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def digest(data: bytes) -> str:
    """Self-describing SHA-256 digest: multibase(multihash(sha256(data)))."""
    return multibase_encode(SHA2_256_MULTIHASH + sha256(data))


# --------------------------------------------------------------------------- #
# Ed25519 keys
# --------------------------------------------------------------------------- #


class KeyPair:
    """An Ed25519 keypair. Public keys are exchanged as multibase multikeys."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._sk = private_key
        self._pk = private_key.public_key()

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "KeyPair":
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def seed(self) -> bytes:
        return self._sk.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    @property
    def public_bytes(self) -> bytes:
        return self._pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @property
    def public_multikey(self) -> str:
        return public_key_to_multikey(self.public_bytes)

    def sign(self, message: bytes) -> str:
        return b64u(self._sk.sign(message))


def public_key_to_multikey(raw: bytes) -> str:
    if len(raw) != 32:
        raise ValueError("Ed25519 public keys are 32 bytes")
    return multibase_encode(ED25519_PUB_CODEC + raw)


def multikey_to_public_key(multikey: str) -> bytes:
    data = multibase_decode(multikey)
    if not data.startswith(ED25519_PUB_CODEC) or len(data) != 34:
        raise ValueError("not an Ed25519 multikey")
    return data[2:]


def verify(multikey: str, message: bytes, signature_b64u: str) -> bool:
    try:
        pk = Ed25519PublicKey.from_public_bytes(multikey_to_public_key(multikey))
        pk.verify(b64u_decode(signature_b64u), message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def key_commitment(multikey: str) -> str:
    """Pre-rotation commitment: a digest of the *next* public key."""
    return digest(multikey.encode())

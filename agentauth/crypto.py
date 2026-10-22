"""Low-level primitives: Ed25519 keys, base58btc/multibase, canonical JSON, digests.

Everything here is deterministic and dependency-light so that any relying party
can re-implement verification in another language.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Any, Protocol, runtime_checkable

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
    if not isinstance(s, str):
        raise ValueError("base58 input must be a string")
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
    if not isinstance(s, str) or not s.startswith("z"):
        raise ValueError("only base58btc multibase ('z') is supported")
    return b58decode(s[1:])


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


_B64U_RE = re.compile(r"\A[A-Za-z0-9_-]*\Z")

# Largest integer every JSON implementation represents exactly (2**53 - 1).
MAX_SAFE_INT = 9007199254740991


def b64u_decode(s: str) -> bytes:
    """Strict, canonical base64url decoding (no padding, no stray characters).

    The standard library silently discards characters outside the alphabet and
    accepts non-zero trailing bits, so several strings would decode to the same
    bytes. Verifiers must only accept the one encoding `b64u` produces.
    """
    if not isinstance(s, str) or not _B64U_RE.match(s) or len(s) % 4 == 1:
        raise ValueError("not canonical unpadded base64url")
    try:
        out = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError):
        raise ValueError("not canonical unpadded base64url") from None
    if b64u(out) != s:
        raise ValueError("not canonical unpadded base64url")
    return out


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
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    except UnicodeEncodeError:
        # e.g. lone surrogates, which have no UTF-8 encoding
        raise TypeError("strings in signed payloads must be valid Unicode") from None


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def digest(data: bytes) -> str:
    """Self-describing SHA-256 digest: multibase(multihash(sha256(data)))."""
    return multibase_encode(SHA2_256_MULTIHASH + sha256(data))


# --------------------------------------------------------------------------- #
# Ed25519 keys
# --------------------------------------------------------------------------- #


@runtime_checkable
class Signer(Protocol):
    """Anything that can sign with an Ed25519 key.

    `KeyPair` is the in-process implementation. To keep a key in an HSM, KMS
    or a signing service, wrap it in an object with these two members and pass
    it wherever the SDK accepts a key (e.g. as a recovery key for rotation).
    """

    @property
    def public_multikey(self) -> str: ...

    def sign(self, message: bytes) -> str:
        """Return the base64url (unpadded) Ed25519 signature over `message`."""
        ...


class KeyPair:
    """An Ed25519 keypair. Public keys are exchanged as multibase multikeys."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._sk = private_key
        self._pk = private_key.public_key()

    @classmethod
    def generate(cls) -> KeyPair:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> KeyPair:
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
    if not isinstance(multikey, str) or len(multikey) > 64:
        raise ValueError("not an Ed25519 multikey")
    data = multibase_decode(multikey)
    if not data.startswith(ED25519_PUB_CODEC) or len(data) != 34:
        raise ValueError("not an Ed25519 multikey")
    return data[2:]


def verify(multikey: str, message: bytes, signature_b64u: str) -> bool:
    """Verify an Ed25519 signature. Never raises: anything malformed is just invalid."""
    try:
        sig = b64u_decode(signature_b64u)
        if len(sig) != 64:
            return False
        pk = Ed25519PublicKey.from_public_bytes(multikey_to_public_key(multikey))
        pk.verify(sig, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def is_digest(value: Any) -> bool:
    """Is `value` a well-formed `digest()` string (multibase sha2-256 multihash)?"""
    if not isinstance(value, str) or not value.startswith("z") or len(value) > 64:
        return False
    try:
        raw = multibase_decode(value)
    except ValueError:
        return False
    return len(raw) == 34 and raw.startswith(SHA2_256_MULTIHASH)


def key_commitment(multikey: str) -> str:
    """Pre-rotation commitment: a digest of the *next* public key."""
    return digest(multikey.encode())

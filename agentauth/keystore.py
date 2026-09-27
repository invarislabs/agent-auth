"""On-disk key storage.

Keys are split across two files on purpose:

* ``<name>.key.json``       – the *current* signing key. The running agent needs this.
* ``<name>.recovery.json``  – the pre-committed *next* key. Needed only to rotate
                              or self-deactivate. Keep it somewhere the agent
                              runtime can't reach (another machine, a vault, KMS).

Either file can be encrypted at rest with a passphrase (scrypt + AES-256-GCM).
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .crypto import KeyPair, b64u, b64u_decode

FORMAT = "agentauth-key/1"


def _kdf(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode())


def _seal(seed: bytes, passphrase: Optional[str]) -> dict:
    if not passphrase:
        return {"enc": "none", "seed": b64u(seed)}
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    ct = AESGCM(_kdf(passphrase, salt)).encrypt(nonce, seed, FORMAT.encode())
    return {"enc": "scrypt-aes256gcm", "salt": b64u(salt), "nonce": b64u(nonce), "ct": b64u(ct)}


def _open(blob: dict, passphrase: Optional[str]) -> bytes:
    if blob.get("enc") == "none":
        return b64u_decode(blob["seed"])
    if blob.get("enc") == "scrypt-aes256gcm":
        if not passphrase:
            raise ValueError("key file is encrypted; set AGENTAUTH_PASSPHRASE or pass a passphrase")
        key = _kdf(passphrase, b64u_decode(blob["salt"]))
        return AESGCM(key).decrypt(b64u_decode(blob["nonce"]), b64u_decode(blob["ct"]), FORMAT.encode())
    raise ValueError(f"unknown key encryption {blob.get('enc')!r}")


def write_key_file(path: Path, *, did: str, role: str, key: KeyPair, extra: dict, passphrase: Optional[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"format": FORMAT, "did": did, "role": role, "public": key.public_multikey, **extra, "secret": _seal(key.seed, passphrase)}
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f, indent=2)
    os.replace(tmp, path)


def read_key_file(path: Path, passphrase: Optional[str]) -> tuple:
    doc = json.loads(Path(path).read_text())
    if doc.get("format") != FORMAT:
        raise ValueError(f"{path} is not an AgentAuth key file")
    key = KeyPair.from_seed(_open(doc["secret"], passphrase))
    if key.public_multikey != doc["public"]:
        raise ValueError(f"{path}: secret does not match recorded public key")
    return doc, key

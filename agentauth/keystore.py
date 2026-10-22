"""On-disk key storage.

Keys are split across files on purpose:

* ``<name>.key.json``       – the *current* signing key. The running agent needs this.
* ``<name>.recovery.json``  – the pre-committed *next* key. Needed only to rotate
                              or self-deactivate. Keep it somewhere the agent
                              runtime can't reach (another machine, a vault, KMS).
* ``<name>.pending.json``   – only during a rotation: the key the rotation commits
                              to next. Written before the rotation is submitted so
                              a crash can never lose it (see
                              `AgentIdentity.rotate_and_save`).

Every file can be encrypted at rest with a passphrase (scrypt + AES-256-GCM).
New files record their scrypt parameters; files written by v0.3 (which didn't)
are read with the v0.3 parameters.

Writes are atomic and durable: a uniquely named temporary file is created
with O_EXCL (never following a pre-planted symlink), written with mode 0600,
fsynced, renamed into place, and the directory is fsynced.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import sys
import warnings
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .crypto import KeyPair, Signer, b64u, b64u_decode

FORMAT = "agentauth-key/1"
# OWASP-recommended minimum for scrypt (2**17, r=8, p=1): ~128 MiB, ~0.3-0.5 s.
SCRYPT_PARAMS = {"n": 2**17, "r": 8, "p": 1}
_V03_SCRYPT_PARAMS = {"n": 2**15, "r": 8, "p": 1}
_MAX_SCRYPT_N = 2**20


class KeyFileError(ValueError):
    pass


class InsecureKeyFileWarning(UserWarning):
    pass


def _kdf(passphrase: str, salt: bytes, params: dict) -> bytes:
    n, r, p = params["n"], params["r"], params["p"]
    if not (isinstance(n, int) and 2**14 <= n <= _MAX_SCRYPT_N and n & (n - 1) == 0 and r in range(1, 33) and p in range(1, 17)):
        raise KeyFileError("unsupported scrypt parameters in key file")
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode())


def _seal(seed: bytes, passphrase: Optional[str]) -> dict:
    if not passphrase:
        return {"enc": "none", "seed": b64u(seed)}
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    ct = AESGCM(_kdf(passphrase, salt, SCRYPT_PARAMS)).encrypt(nonce, seed, FORMAT.encode())
    return {"enc": "scrypt-aes256gcm", "kdf": dict(SCRYPT_PARAMS), "salt": b64u(salt), "nonce": b64u(nonce), "ct": b64u(ct)}


def _open(blob: dict, passphrase: Optional[str]) -> bytes:
    if not isinstance(blob, dict):
        raise KeyFileError("malformed key file")
    if blob.get("enc") == "none":
        return b64u_decode(blob["seed"])
    if blob.get("enc") == "scrypt-aes256gcm":
        if not passphrase:
            raise KeyFileError("key file is encrypted; set AGENTAUTH_PASSPHRASE or pass a passphrase")
        params = blob.get("kdf") or _V03_SCRYPT_PARAMS
        key = _kdf(passphrase, b64u_decode(blob["salt"]), params)
        try:
            return AESGCM(key).decrypt(b64u_decode(blob["nonce"]), b64u_decode(blob["ct"]), FORMAT.encode())
        except InvalidTag:
            raise KeyFileError("wrong passphrase, or the key file is corrupted") from None
    raise KeyFileError(f"unknown key encryption {blob.get('enc')!r}")


def _fsync_dir(path: Path) -> None:
    if sys.platform == "win32":  # pragma: no cover - directories can't be fsynced on Windows
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_key_file(path: Path, *, did: str, role: str, key: Signer, extra: dict, passphrase: Optional[str]) -> None:
    if not isinstance(key, KeyPair):
        raise KeyFileError("only in-process KeyPairs can be written to key files; external signers keep their own keys")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    doc = {"format": FORMAT, "did": did, "role": role, "public": key.public_multikey, **extra,
           "secret": _seal(key.seed, passphrase)}
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    _fsync_dir(path.parent)


def remove_key_file(path: Path) -> None:
    """Delete a key file (e.g. a completed pending rotation) durably."""
    path = Path(path)
    try:
        os.unlink(path)
    except FileNotFoundError:
        return
    _fsync_dir(path.parent)


def check_permissions(path: Path) -> None:
    """Warn when a key file is readable or writable by other users."""
    if sys.platform == "win32":  # pragma: no cover
        return
    mode = os.stat(path).st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        warnings.warn(f"{path} is accessible by other users (mode {stat.S_IMODE(mode):o}); chmod 600 it",
                      InsecureKeyFileWarning, stacklevel=3)


def read_key_file(path: Path, passphrase: Optional[str]) -> tuple:
    path = Path(path)
    check_permissions(path)
    try:
        doc = json.loads(path.read_text())
    except ValueError:
        raise KeyFileError(f"{path} is not valid JSON") from None
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise KeyFileError(f"{path} is not an AgentAuth key file")
    try:
        key = KeyPair.from_seed(_open(doc["secret"], passphrase))
    except (KeyError, TypeError) as e:
        raise KeyFileError(f"{path}: malformed key file ({e})") from None
    if key.public_multikey != doc.get("public"):
        raise KeyFileError(f"{path}: secret does not match recorded public key")
    return doc, key


def is_encrypted(path: Path) -> bool:
    doc = json.loads(Path(path).read_text())
    return doc.get("secret", {}).get("enc") != "none"

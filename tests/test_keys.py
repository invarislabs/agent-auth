"""Key custody: crash-safe rotation, key file hardening, external signers."""

import json
import os
import stat
import warnings

import pytest
from conftest import new_agent

from agentauth import AgentIdentity, KeyPair, RegistryError, Signer
from agentauth.crypto import b64u
from agentauth.keystore import (
    FORMAT,
    InsecureKeyFileWarning,
    KeyFileError,
    _kdf,
    read_key_file,
    write_key_file,
)


class Crash(Exception):
    pass


def test_crash_after_submit_is_recoverable(registry, tmp_path):
    """The process dies after the registry accepted the rotation but before keys were saved."""
    reg, _ = registry
    keys, vault = tmp_path / "keys", tmp_path / "vault"
    agent = new_agent(reg, name="r")
    agent.save(keys, "r", passphrase="pw", recovery_dir=vault)

    ident = AgentIdentity.load(keys, "r", passphrase="pw", recovery_dir=vault)
    original = reg.verified_state

    def die(did):
        raise Crash("power cut")

    reg.verified_state = die
    with pytest.raises(Crash):
        ident.rotate_and_save(reg, keys, "r", passphrase="pw", recovery_dir=vault)
    reg.verified_state = original
    assert (vault / "r.pending.json").exists()
    assert reg.verified_state(agent.did).seq == 1  # the registry did apply it

    resumed = AgentIdentity.load(keys, "r", passphrase="pw", recovery_dir=vault)
    assert resumed.pending_next_key is not None
    resumed.rotate_and_save(reg, keys, "r", passphrase="pw", recovery_dir=vault)
    assert not (vault / "r.pending.json").exists()
    assert reg.whoami(resumed)["kid"].endswith("#key-1")

    # And the identity can keep rotating: the next key wasn't lost.
    again = AgentIdentity.load(keys, "r", passphrase="pw", recovery_dir=vault)
    again.rotate_and_save(reg, keys, "r", passphrase="pw", recovery_dir=vault)
    assert reg.whoami(again)["kid"].endswith("#key-2")


def test_crash_before_submit_retries_with_same_key(registry, tmp_path):
    reg, _ = registry
    agent = new_agent(reg, name="b")
    agent.save(tmp_path, "b", passphrase="pw")
    ident = AgentIdentity.load(tmp_path, "b", passphrase="pw")
    original = reg.submit

    def die(did, ev):
        raise Crash("network gone")

    reg.submit = die
    with pytest.raises(Crash):
        ident.rotate_and_save(reg, tmp_path, "b", passphrase="pw")
    reg.submit = original
    pending_pub = json.loads((tmp_path / "b.pending.json").read_text())["public"]

    resumed = AgentIdentity.load(tmp_path, "b", passphrase="pw")
    resumed.rotate_and_save(reg, tmp_path, "b", passphrase="pw")
    assert reg.verified_state(agent.did).next is not None
    assert resumed.recovery_key.public_multikey == pending_pub  # the saved key was used, not a new one


def test_commit_refuses_state_without_the_event(registry):
    reg, _ = registry
    agent = new_agent(reg, name="c")
    agent.prepare_rotation()
    with pytest.raises(RuntimeError, match="does not contain"):
        agent.commit(reg.verified_state(agent.did))  # never submitted
    assert agent.kid.endswith("#key-0")


def test_identity_rejects_mismatched_key(registry):
    reg, _ = registry
    agent = new_agent(reg, name="m")
    with pytest.raises(ValueError):
        AgentIdentity(agent.state, KeyPair.generate(), None)


def test_refresh_detects_rotation_elsewhere(registry, tmp_path):
    reg, _ = registry
    agent = new_agent(reg, name="e")
    agent.save(tmp_path, "e", passphrase="pw")
    stale = AgentIdentity.load(tmp_path, "e", passphrase="pw")
    reg.rotate(agent)
    with pytest.raises(RuntimeError, match="different key"):
        stale.refresh(reg)


def test_v03_key_files_still_load(tmp_path):
    """Files written by v0.3 didn't record scrypt parameters (n=2**15)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    kp = KeyPair.generate()
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(_kdf("pw", salt, {"n": 2**15, "r": 8, "p": 1})).encrypt(nonce, kp.seed, FORMAT.encode())
    doc = {"format": FORMAT, "did": "did:agent:x", "role": "current", "public": kp.public_multikey,
           "secret": {"enc": "scrypt-aes256gcm", "salt": b64u(salt), "nonce": b64u(nonce), "ct": b64u(ct)}}
    p = tmp_path / "old.key.json"
    p.write_text(json.dumps(doc))
    os.chmod(p, 0o600)
    _, loaded = read_key_file(p, "pw")
    assert loaded.public_multikey == kp.public_multikey


def test_new_files_record_strong_kdf_and_tight_permissions(tmp_path):
    kp = KeyPair.generate()
    write_key_file(tmp_path / "sub" / "k.json", did="d", role="current", key=kp, extra={}, passphrase="pw")
    doc = json.loads((tmp_path / "sub" / "k.json").read_text())
    assert doc["secret"]["kdf"]["n"] >= 2**17
    assert stat.S_IMODE((tmp_path / "sub" / "k.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "sub").stat().st_mode) & 0o077 == 0
    assert not [f for f in os.listdir(tmp_path / "sub") if f.endswith(".tmp")]
    with pytest.raises(KeyFileError, match="passphrase"):
        read_key_file(tmp_path / "sub" / "k.json", "wrong")


def test_preplanted_symlink_is_not_followed(tmp_path):
    """v0.3 wrote to a predictable `<file>.tmp`; a symlink there would have received the secret."""
    target = tmp_path / "stolen"
    (tmp_path / "k.json.tmp").symlink_to(target)
    write_key_file(tmp_path / "k.json", did="d", role="current", key=KeyPair.generate(), extra={}, passphrase=None)
    assert not target.exists()


def test_group_readable_key_file_warns(tmp_path):
    kp = KeyPair.generate()
    write_key_file(tmp_path / "k.json", did="d", role="current", key=kp, extra={}, passphrase=None)
    os.chmod(tmp_path / "k.json", 0o640)  # any group/other access triggers the warning
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        read_key_file(tmp_path / "k.json", None)
    assert any(issubclass(x.category, InsecureKeyFileWarning) for x in w)


@pytest.mark.parametrize("params", [{"n": 2**30, "r": 8, "p": 1}, {"n": 1000, "r": 8, "p": 1}, {"n": 2**15, "r": 0, "p": 1}])
def test_hostile_kdf_parameters_refused(tmp_path, params):
    """A tampered file can't make us burn unbounded memory/CPU deriving a key."""
    doc = {"format": FORMAT, "did": "d", "role": "current", "public": "z",
           "secret": {"enc": "scrypt-aes256gcm", "kdf": params, "salt": b64u(b"s" * 16), "nonce": b64u(b"n" * 12),
                      "ct": b64u(b"c" * 48)}}
    p = tmp_path / "evil.json"
    p.write_text(json.dumps(doc))
    os.chmod(p, 0o600)
    with pytest.raises(KeyFileError, match="scrypt"):
        read_key_file(p, "pw")


@pytest.mark.parametrize("name", ["../escape", "a/b", ".hidden", ""])
def test_identity_names_cannot_escape_directory(tmp_path, name):
    ident, _ = AgentIdentity.create(name="x")
    with pytest.raises(ValueError):
        ident.save(tmp_path, name, passphrase="pw")


class HsmSigner:
    """Stands in for a key held in an HSM/KMS: the private key never leaves this object."""

    def __init__(self):
        self._kp = KeyPair.generate()
        self.signed = 0

    @property
    def public_multikey(self):
        return self._kp.public_multikey

    def sign(self, message):
        self.signed += 1
        return self._kp.sign(message)


def test_external_signer_can_hold_the_recovery_key(registry):
    reg, _ = registry
    hsm = HsmSigner()
    assert isinstance(hsm, Signer)
    from agentauth.identity import make_inception, verify_inception

    current = KeyPair.generate()
    ev = make_inception(current, hsm, meta={"name": "hsm-backed"})
    reg.register(ev)
    agent = AgentIdentity(verify_inception(ev, lambda d, k: True), current, hsm)
    next_hsm = HsmSigner()
    event = agent.prepare_rotation(next_hsm)
    reg.submit(agent.did, event)
    agent.commit(reg.verified_state(agent.did))
    assert hsm.signed == 1 and agent.current_key is hsm and agent.recovery_key is next_hsm
    assert reg.whoami(agent)["kid"].endswith("#key-1")
    with pytest.raises(KeyFileError):
        write_key_file(__import__("pathlib").Path("/nonexistent/x"), did="d", role="current", key=hsm, extra={},
                       passphrase=None)


def test_deactivated_identity_cannot_rotate(registry):
    reg, _ = registry
    agent = new_agent(reg, name="dead")
    reg.deactivate_self(agent)
    with pytest.raises(RuntimeError):
        agent.prepare_rotation()
    with pytest.raises(RuntimeError):
        agent.grant("did:agent:" + "1" * 45, ["a"], ["svc"])
    assert isinstance(RegistryError(400, "x"), Exception)

import base64
import hashlib
import os
import stat

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, rsa

from tacstmu.core.constants import PROFILES, PROFILE_ECDSA, PROFILE_ED25519, PROFILE_RSA
from tacstmu.core.outcomes import FormatError, InputError, UnsupportedAlgorithmError
from tacstmu.crypto import keys

P256_SPKI_COMPRESSED_PREFIX = bytes.fromhex("3039301306072a8648ce3d020106082a8648ce3d030107032200")
ED25519_SPKI_WITH_NULL_PARAMS_PREFIX = bytes.fromhex("302c300706032b65700500032100")


@pytest.fixture(scope="module")
def generated():
    return {profile: keys.generate(profile) for profile in PROFILES}


def _der_to_pem(der: bytes, label: str, width: int = 64, newline: bytes = b"\n") -> bytes:
    body = base64.b64encode(der)
    lines = [body[i : i + width] for i in range(0, len(body), width)]
    return newline.join([f"-----BEGIN {label}-----".encode(), *lines, f"-----END {label}-----".encode(), b""])


# Generation and round trips
@pytest.mark.parametrize("profile", PROFILES)
def test_round_trip(generated, profile):
    key = generated[profile]
    priv_pem, pub_pem = keys.private_pem(key), keys.public_pem(key.public_key())
    assert priv_pem.startswith(b"-----BEGIN PRIVATE KEY-----\n")
    assert pub_pem.startswith(b"-----BEGIN PUBLIC KEY-----\n")

    loaded_key, key_profile = keys.load_private_pem(priv_pem)
    loaded_pub, pub_profile = keys.load_public_pem(pub_pem)
    assert key_profile == pub_profile == profile
    assert keys.keyid(loaded_key.public_key()) == keys.keyid(loaded_pub)

def test_generated_parameters(generated):
    rsa_pub = generated[PROFILE_RSA].public_key()
    assert rsa_pub.key_size == 3072 and rsa_pub.public_numbers().e == 65537
    assert isinstance(generated[PROFILE_ECDSA].curve, ec.SECP256R1)

def test_generate_unknown_profile():
    with pytest.raises(UnsupportedAlgorithmError):
        keys.generate("dsa-sha1")


# keyid
def test_keyid_is_sha256_of_der_and_ignores_pem_formatting(generated):
    pub = generated[PROFILE_ECDSA].public_key()
    der = keys.public_der(pub)
    assert keys.keyid(pub) == hashlib.sha256(der).hexdigest()

    reformatted = _der_to_pem(der, "PUBLIC KEY", width=20, newline=b"\r\n")
    assert keys.keyid(keys.load_public_pem(reformatted)[0]) == keys.keyid(pub)


# Rejected private keys
@pytest.mark.parametrize(
    "make_key",
    [
        pytest.param(lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048), id="rsa-2048"),
        pytest.param(lambda: ec.generate_private_key(ec.SECP384R1()), id="p384"),
        pytest.param(lambda: ed448.Ed448PrivateKey.generate(), id="ed448"),
    ],
)
def test_rejects_wrong_key_params(make_key):
    pem = make_key().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    with pytest.raises(InputError):
        keys.load_private_pem(pem)

def test_rejects_traditional_label(generated):
    pem = generated[PROFILE_RSA].private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )
    with pytest.raises(InputError, match="RSA PRIVATE KEY"):
        keys.load_private_pem(pem)

def test_rejects_encrypted_private_key(generated):
    pem = generated[PROFILE_ED25519].private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"secret"),
    )
    with pytest.raises(InputError, match="ENCRYPTED PRIVATE KEY"):
        keys.load_private_pem(pem)

def test_rejects_garbage():
    with pytest.raises(InputError):
        keys.load_private_pem(b"not a key")


# Rejected public keys
def test_rejects_pkcs1_public_label(generated):
    pem = generated[PROFILE_RSA].public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.PKCS1
    )
    with pytest.raises(FormatError, match="RSA PUBLIC KEY"):
        keys.load_public_pem(pem)

def test_rejects_compressed_p256_point(generated):
    point = generated[PROFILE_ECDSA].public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )
    with pytest.raises(FormatError, match="standard SPKI"):
        keys.load_public_pem(_der_to_pem(P256_SPKI_COMPRESSED_PREFIX + point, "PUBLIC KEY"))

def test_rejects_ed25519_with_parameters(generated):
    raw = generated[PROFILE_ED25519].public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    with pytest.raises(FormatError):
        keys.load_public_pem(_der_to_pem(ED25519_SPKI_WITH_NULL_PARAMS_PREFIX + raw, "PUBLIC KEY"))

def test_rejects_two_pem_blocks(generated):
    pem = keys.public_pem(generated[PROFILE_ED25519].public_key())
    with pytest.raises(FormatError):
        keys.load_public_pem(pem + pem)


# Key file writing
def test_write_keypair_creates_files(tmp_path, generated):
    private_path, public_path = keys.write_keypair(tmp_path / "keys" / "publisher", generated[PROFILE_ED25519])
    assert private_path == tmp_path / "keys" / "publisher.key.pem"
    assert public_path == tmp_path / "keys" / "publisher.pub.pem"
    assert keys.load_private_pem(private_path.read_bytes())[1] == PROFILE_ED25519
    if os.name != "nt":  # Windows stat modes do not represent ACL privacy.
        assert stat.S_IMODE(private_path.stat().st_mode) == 0o600

def test_write_keypair_refuses_overwrite(tmp_path, generated):
    keys.write_keypair(tmp_path / "pub", generated[PROFILE_ED25519])
    before = (tmp_path / "pub.key.pem").read_bytes()
    with pytest.raises(InputError, match="overwrite"):
        keys.write_keypair(tmp_path / "pub", generated[PROFILE_ECDSA])
    assert (tmp_path / "pub.key.pem").read_bytes() == before

def test_write_keypair_refuses_if_only_public_exists(tmp_path, generated):
    (tmp_path / "pub.pub.pem").write_bytes(b"old")
    with pytest.raises(InputError):
        keys.write_keypair(tmp_path / "pub", generated[PROFILE_ED25519])
    assert not (tmp_path / "pub.key.pem").exists()

def test_write_keypair_force_overwrites(tmp_path, generated):
    private_path = tmp_path / "pub.key.pem"
    private_path.write_bytes(b"old")
    private_path.chmod(0o644)
    keys.write_keypair(tmp_path / "pub", generated[PROFILE_ECDSA], force=True)
    assert keys.load_private_pem(private_path.read_bytes())[1] == PROFILE_ECDSA
    if os.name != "nt":  # Windows stat modes do not represent ACL privacy.
        assert stat.S_IMODE(private_path.stat().st_mode) == 0o600


def test_write_keypair_without_fchmod(tmp_path, generated, monkeypatch):
    monkeypatch.delattr(keys.os, "fchmod", raising=False)
    private, public = keys.write_keypair(tmp_path / "portable", generated[PROFILE_ED25519])
    assert keys.load_private_pem(private.read_bytes())[1] == PROFILE_ED25519
    assert keys.load_public_pem(public.read_bytes())[1] == PROFILE_ED25519


def test_write_keypair_applies_fchmod_when_available(tmp_path, generated, monkeypatch):
    calls = []
    original = getattr(keys.os, "fchmod", None)
    def record(fd, mode):
        calls.append(mode)
        if original is not None:
            original(fd, mode)
    monkeypatch.setattr(keys.os, "fchmod", record, raising=False)
    private, public = keys.write_keypair(tmp_path / "permissions", generated[PROFILE_ED25519])
    assert calls == [0o600, 0o644]
    assert keys.load_private_pem(private.read_bytes())[1] == PROFILE_ED25519
    assert keys.load_public_pem(public.read_bytes())[1] == PROFILE_ED25519

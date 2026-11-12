import hashlib

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature

from tacstmu.core.constants import PROFILES, PROFILE_ECDSA, PROFILE_ED25519, PROFILE_RSA
from tacstmu.core.outcomes import FormatError, UnsupportedAlgorithmError
from tacstmu.crypto import keys
from tacstmu.crypto.signature import sign, verify

MESSAGE = (
    b'{"schema":"minisign-manifest/v1","package":"contoh-app","version":"1.0.0",'
    b'"algorithm":"ed25519","keyid":"' + b"0" * 64 + b'","artifact":{"name":"contoh-app.zip",'
    b'"size":3,"sha256":"' + b"0" * 64 + b'"}}'
)
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


@pytest.fixture(scope="module")
def keyset():
    return {profile: keys.generate(profile) for profile in PROFILES}

@pytest.fixture(scope="module")
def other_keyset():
    return {profile: keys.generate(profile) for profile in PROFILES}


# Round trips and sizes
@pytest.mark.parametrize("profile, length", [(PROFILE_RSA, 384), (PROFILE_ECDSA, 64), (PROFILE_ED25519, 64)])
def test_sign_and_verify(keyset, profile, length):
    key = keyset[profile]
    sig = sign(profile, key, MESSAGE)
    assert len(sig) == length
    assert verify(profile, key.public_key(), MESSAGE, sig)

@pytest.mark.parametrize("profile", PROFILES)
def test_empty_message(keyset, profile):
    key = keyset[profile]
    assert verify(profile, key.public_key(), b"", sign(profile, key, b""))


# Rejected signatures
@pytest.mark.parametrize("profile", PROFILES)
def test_changed_message(keyset, profile):
    key = keyset[profile]
    sig = sign(profile, key, MESSAGE)
    tampered = MESSAGE.replace(b"1.0.0", b"1.0.1")
    assert not verify(profile, key.public_key(), tampered, sig)

@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("index", [0, 12, 32, -1])
def test_flipped_signature_bit(keyset, profile, index):
    key = keyset[profile]
    sig = bytearray(sign(profile, key, MESSAGE))
    sig[index] ^= 0x01
    assert not verify(profile, key.public_key(), MESSAGE, bytes(sig))

@pytest.mark.parametrize("profile", PROFILES)
def test_wrong_key_same_profile(keyset, other_keyset, profile):
    sig = sign(profile, keyset[profile], MESSAGE)
    assert not verify(profile, other_keyset[profile].public_key(), MESSAGE, sig)

@pytest.mark.parametrize("profile", PROFILES)
def test_wrong_length(keyset, profile):
    key = keyset[profile]
    sig = sign(profile, key, MESSAGE)
    for bad in (b"", sig[:-1], sig + b"\x00"):
        assert not verify(profile, key.public_key(), MESSAGE, bad)

@pytest.mark.parametrize(
    "r, s",
    [(0, 1), (1, 0), (P256_ORDER, 1), (1, P256_ORDER), (2**256 - 1, 2**256 - 1)],
)
def test_ecdsa_out_of_range_scalars(keyset, r, s):
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert not verify(PROFILE_ECDSA, keyset[PROFILE_ECDSA].public_key(), MESSAGE, sig)


# Spec parameters: single hashing, salt length, r||s format
def test_rsa_hashes_message_once(keyset):
    key = keyset[PROFILE_RSA]
    sig = sign(PROFILE_RSA, key, MESSAGE)
    digest = hashlib.sha256(MESSAGE).digest()
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    key.public_key().verify(sig, digest, pss, Prehashed(hashes.SHA256()))

def test_rsa_salt_length_is_32(keyset):
    key = keyset[PROFILE_RSA]
    sig = sign(PROFILE_RSA, key, MESSAGE)
    pss_31 = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=31)
    with pytest.raises(InvalidSignature):
        key.public_key().verify(sig, MESSAGE, pss_31, hashes.SHA256())

def test_ecdsa_hashes_message_once(keyset):
    key = keyset[PROFILE_ECDSA]
    sig = sign(PROFILE_ECDSA, key, MESSAGE)
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    digest = hashlib.sha256(MESSAGE).digest()
    key.public_key().verify(der, digest, ec.ECDSA(Prehashed(hashes.SHA256())))

def test_ecdsa_raw_signature_verifies_as_der(keyset):
    key = keyset[PROFILE_ECDSA]
    sig = sign(PROFILE_ECDSA, key, MESSAGE)
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    key.public_key().verify(der, MESSAGE, ec.ECDSA(hashes.SHA256()))


# Signing the same message twice
def test_ed25519_is_deterministic(keyset):
    key = keyset[PROFILE_ED25519]
    assert sign(PROFILE_ED25519, key, MESSAGE) == sign(PROFILE_ED25519, key, MESSAGE)

@pytest.mark.parametrize("profile", [PROFILE_RSA, PROFILE_ECDSA])
def test_randomized_profiles_differ(keyset, profile):
    key = keyset[profile]
    first, second = sign(profile, key, MESSAGE), sign(profile, key, MESSAGE)
    assert first != second
    assert verify(profile, key.public_key(), MESSAGE, first)
    assert verify(profile, key.public_key(), MESSAGE, second)


# Caller errors
def test_unknown_profile(keyset):
    with pytest.raises(UnsupportedAlgorithmError):
        sign("rsa-pkcs1-sha1", keyset[PROFILE_RSA], MESSAGE)
    with pytest.raises(UnsupportedAlgorithmError):
        verify("rsa-pkcs1-sha1", keyset[PROFILE_RSA].public_key(), MESSAGE, b"")

def test_key_profile_mismatch(keyset):
    with pytest.raises(FormatError):
        sign(PROFILE_RSA, keyset[PROFILE_ED25519], MESSAGE)
    with pytest.raises(FormatError):
        verify(PROFILE_ED25519, keyset[PROFILE_ECDSA].public_key(), MESSAGE, b"\x00" * 64)

def test_private_key_rejected_for_verify(keyset):
    with pytest.raises(FormatError):
        verify(PROFILE_ED25519, keyset[PROFILE_ED25519], MESSAGE, b"\x00" * 64)

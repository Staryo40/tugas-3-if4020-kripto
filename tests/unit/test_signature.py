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

MESSAGE = b'{"schema":"minisign-manifest/v1","package":"contoh-app","version":"1.0.0"}'
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


@pytest.fixture(scope="module")
def keyset():
    return {profile: keys.generate(profile) for profile in PROFILES}


# Round trips and sizes
@pytest.mark.parametrize("profile, length", [(PROFILE_RSA, 384), (PROFILE_ECDSA, 64), (PROFILE_ED25519, 64)])
def test_sign_and_verify(keyset, profile, length):
    key = keyset[profile]
    sig = sign(profile, key, MESSAGE)
    assert len(sig) == length
    assert verify(profile, key.public_key(), MESSAGE, sig)


# Rejected signatures
@pytest.mark.parametrize("profile", PROFILES)
def test_flipped_signature_bit(keyset, profile):
    key = keyset[profile]
    sig = bytearray(sign(profile, key, MESSAGE))
    sig[12] ^= 0x01
    assert not verify(profile, key.public_key(), MESSAGE, bytes(sig))

def test_changed_message(keyset):
    key = keyset[PROFILE_ED25519]
    sig = sign(PROFILE_ED25519, key, MESSAGE)
    assert not verify(PROFILE_ED25519, key.public_key(), MESSAGE.replace(b"1.0.0", b"1.0.1"), sig)

def test_wrong_key_same_profile(keyset):
    sig = sign(PROFILE_ECDSA, keyset[PROFILE_ECDSA], MESSAGE)
    other = keys.generate(PROFILE_ECDSA)
    assert not verify(PROFILE_ECDSA, other.public_key(), MESSAGE, sig)

def test_wrong_length(keyset):
    key = keyset[PROFILE_RSA]
    sig = sign(PROFILE_RSA, key, MESSAGE)
    assert not verify(PROFILE_RSA, key.public_key(), MESSAGE, sig[:-1])

@pytest.mark.parametrize("r, s", [(0, 1), (P256_ORDER, 1)])
def test_ecdsa_out_of_range_scalars(keyset, r, s):
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert not verify(PROFILE_ECDSA, keyset[PROFILE_ECDSA].public_key(), MESSAGE, sig)


# Spec parameters: single hashing, salt length, r||s format
def test_rsa_hashes_message_once(keyset):
    key = keyset[PROFILE_RSA]
    sig = sign(PROFILE_RSA, key, MESSAGE)
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    key.public_key().verify(sig, hashlib.sha256(MESSAGE).digest(), pss, Prehashed(hashes.SHA256()))

def test_rsa_salt_length_is_32(keyset):
    key = keyset[PROFILE_RSA]
    sig = sign(PROFILE_RSA, key, MESSAGE)
    pss_31 = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=31)
    with pytest.raises(InvalidSignature):
        key.public_key().verify(sig, MESSAGE, pss_31, hashes.SHA256())

def test_ecdsa_raw_format_and_single_hash(keyset):
    key = keyset[PROFILE_ECDSA]
    sig = sign(PROFILE_ECDSA, key, MESSAGE)
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    key.public_key().verify(der, hashlib.sha256(MESSAGE).digest(), ec.ECDSA(Prehashed(hashes.SHA256())))


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

def test_key_profile_mismatch(keyset):
    with pytest.raises(FormatError):
        sign(PROFILE_RSA, keyset[PROFILE_ED25519], MESSAGE)

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from ..core.constants import (
    PROFILE_ECDSA,
    PROFILE_ED25519,
    PROFILE_RSA,
    RSA_PSS_SALT_LENGTH,
    SIGNATURE_LENGTH,
)
from ..core.outcomes import FormatError, UnsupportedAlgorithmError
from .keys import PrivateKey, PublicKey

# order of the P-256 base point; valid r and s lie in 1..n-1
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_SCALAR_BYTES = 32

_KEY_TYPES = {
    PROFILE_RSA: (rsa.RSAPrivateKey, rsa.RSAPublicKey),
    PROFILE_ECDSA: (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey),
    PROFILE_ED25519: (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey),
}

def sign(profile: str, key: PrivateKey, message: bytes) -> bytes:
    _require_key_matches(profile, key, private=True)

    if profile == PROFILE_RSA:
        return _rsa_sign(key, message)
    if profile == PROFILE_ECDSA:
        return _ecdsa_sign(key, message)
    
    return _ed25519_sign(key, message)

def verify(profile: str, pub: PublicKey, message: bytes, signature: bytes) -> bool:
    _require_key_matches(profile, pub, private=False)

    if len(signature) != SIGNATURE_LENGTH[profile]:
        return False

    try:
        if profile == PROFILE_RSA:
            _rsa_verify(pub, message, signature)
        elif profile == PROFILE_ECDSA:
            if not _ecdsa_verify(pub, message, signature):
                return False
        else:
            _ed25519_verify(pub, message, signature)
    except (InvalidSignature, ValueError):
        return False

    return True


# Profile and key checks
def _require_key_matches(profile: str, key: PrivateKey | PublicKey, private: bool) -> None:
    if profile not in _KEY_TYPES:
        raise UnsupportedAlgorithmError(f"unsupported algorithm profile '{profile}'")

    expected = _KEY_TYPES[profile][0 if private else 1]
    if not isinstance(key, expected):
        raise FormatError(f"key type '{type(key).__name__}' does not match profile '{profile}'")


# RSA-PSS
def _rsa_padding() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=RSA_PSS_SALT_LENGTH)

def _rsa_sign(key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    return key.sign(message, _rsa_padding(), hashes.SHA256())

def _rsa_verify(pub: rsa.RSAPublicKey, message: bytes, signature: bytes) -> None:
    pub.verify(signature, message, _rsa_padding(), hashes.SHA256())


# ECDSA P-256
def _ecdsa_sign(key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(_P256_SCALAR_BYTES, "big") + s.to_bytes(_P256_SCALAR_BYTES, "big")

def _ecdsa_verify(pub: ec.EllipticCurvePublicKey, message: bytes, signature: bytes) -> bool:
    r = int.from_bytes(signature[:_P256_SCALAR_BYTES], "big")
    s = int.from_bytes(signature[_P256_SCALAR_BYTES:], "big")

    if not (0 < r < _P256_ORDER and 0 < s < _P256_ORDER):
        return False

    pub.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
    return True


# Ed25519
def _ed25519_sign(key: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
    return key.sign(message)

def _ed25519_verify(pub: ed25519.Ed25519PublicKey, message: bytes, signature: bytes) -> None:
    pub.verify(signature, message)

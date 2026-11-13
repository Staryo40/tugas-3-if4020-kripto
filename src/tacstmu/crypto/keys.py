import hashlib
import os
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from ..core import base64 as b64
from ..core.constants import (
    PROFILE_ECDSA,
    PROFILE_ED25519,
    PROFILE_RSA,
    RSA_KEY_BITS,
    RSA_PUBLIC_EXPONENT,
)
from ..core.outcomes import FormatError, InputError, TacstmuError, UnsupportedAlgorithmError

PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey
PublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey

_PRIVATE_LABEL = "PRIVATE KEY"
_PUBLIC_LABEL = "PUBLIC KEY"
_PEM_RE = re.compile(
    rb"\s*-----BEGIN ([A-Z0-9 ]+)-----\r?\n([A-Za-z0-9+/=\s]*?)-----END ([A-Z0-9 ]+)-----\s*"
)

def generate(profile: str) -> PrivateKey:
    if profile == PROFILE_RSA:
        return rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_BITS)
    if profile == PROFILE_ECDSA:
        return ec.generate_private_key(ec.SECP256R1())
    if profile == PROFILE_ED25519:
        return ed25519.Ed25519PrivateKey.generate()
    
    raise UnsupportedAlgorithmError(f"unsupported algorithm profile '{profile}'")

def private_pem(key: PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

def public_pem(pub: PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

def public_der(pub: PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

def keyid(pub: PublicKey) -> str:
    return hashlib.sha256(public_der(pub)).hexdigest()

def load_private_pem(data: bytes) -> tuple[PrivateKey, str]:
    der = _pem_to_der(data, _PRIVATE_LABEL, InputError)

    try:
        key = serialization.load_der_private_key(der, password=None)
    except (ValueError, TypeError) as exc:
        raise InputError(f"invalid private key: {exc}") from None

    return key, _profile_of(key, InputError)

def load_public_pem(data: bytes) -> tuple[PublicKey, str]:
    der = _pem_to_der(data, _PUBLIC_LABEL, FormatError)

    try:
        pub = serialization.load_der_public_key(der)
    except (ValueError, TypeError) as exc:
        raise FormatError(f"invalid public key: {exc}") from None

    profile = _profile_of(pub, FormatError)
    _require_canonical_der(pub, der)

    return pub, profile

def write_keypair(prefix: str | os.PathLike, key: PrivateKey, force: bool = False) -> tuple[Path, Path]:
    private_path = Path(f"{os.fspath(prefix)}.key.pem")
    public_path = Path(f"{os.fspath(prefix)}.pub.pem")

    if not force:
        _refuse_existing(private_path, public_path)

    try:
        private_path.parent.mkdir(parents=True, exist_ok=True)
        _write_file(private_path, private_pem(key), 0o600, exclusive=not force)
        _write_file(public_path, public_pem(key.public_key()), 0o644, exclusive=not force)
    except OSError as exc:
        raise InputError(f"cannot write key files: {exc.strerror or exc}") from None

    return private_path, public_path


# PEM decoding
def _pem_to_der(data: bytes, label: str, error: type[TacstmuError]) -> bytes:
    match = _PEM_RE.fullmatch(data)
    if not match:
        raise error(f"expected exactly one PEM block labelled '{label}'")

    begin, body, end = match.group(1).decode(), match.group(2), match.group(3).decode()
    if begin != end:
        raise error(f"PEM BEGIN label '{begin}' does not match END label '{end}'")
    if begin != label:
        raise error(f"expected PEM label '{label}', got '{begin}'")

    try:
        return b64.decode_strict(re.sub(rb"\s+", b"", body).decode("ascii"))
    except FormatError:
        raise error("PEM body is not valid Base64") from None


# Profile and parameter checks
def _profile_of(key: PrivateKey | PublicKey, error: type[TacstmuError]) -> str:
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        _require_rsa_params(key, error)
        return PROFILE_RSA
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        if not isinstance(key.curve, ec.SECP256R1):
            raise error(f"unsupported curve '{key.curve.name}', expected P-256")
        return PROFILE_ECDSA
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return PROFILE_ED25519
    raise error(f"unsupported key type '{type(key).__name__}'")

def _require_rsa_params(key: rsa.RSAPrivateKey | rsa.RSAPublicKey, error: type[TacstmuError]) -> None:
    pub = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
    if pub.key_size != RSA_KEY_BITS:
        raise error(f"RSA key must be {RSA_KEY_BITS} bits, got {pub.key_size}")
    if pub.public_numbers().e != RSA_PUBLIC_EXPONENT:
        raise error(f"RSA public exponent must be {RSA_PUBLIC_EXPONENT}")

def _require_canonical_der(pub: PublicKey, der: bytes) -> None:
    # rejects compressed points, explicit curve params and non-standard DER
    if public_der(pub) != der:
        raise FormatError("public key is not in standard SPKI encoding")


# Key file writing
def _refuse_existing(*paths: Path) -> None:
    existing = [str(p) for p in paths if p.exists()]
    if existing:
        raise InputError(f"refusing to overwrite existing key file(s): {', '.join(existing)}")

def _write_file(path: Path, data: bytes, mode: int, exclusive: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | (os.O_EXCL if exclusive else 0)
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, "wb") as f:
        # Preserve POSIX permissions, including when overwriting a key.
        # Windows has no fchmod; access there follows the directory ACL.
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        f.write(data)

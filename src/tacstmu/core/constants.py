import re

# Signature algorithm profiles
PROFILE_RSA = "rsa-pss-sha256"
PROFILE_ECDSA = "ecdsa-p256-sha256"
PROFILE_ED25519 = "ed25519"
PROFILES = (PROFILE_RSA, PROFILE_ECDSA, PROFILE_ED25519)

# Raw signature length in bytes, before Base64
SIGNATURE_LENGTH = {
    PROFILE_RSA: 384,
    PROFILE_ECDSA: 64,
    PROFILE_ED25519: 64,
}

# Crypto parameters
RSA_KEY_BITS = 3072
RSA_PUBLIC_EXPONENT = 65537
RSA_PSS_SALT_LENGTH = 32

# Fixed schema identifiers for the file formats
SCHEMA_MANIFEST = "minisign-manifest/v1"
SCHEMA_BUNDLE = "minisign-bundle/v1"
SCHEMA_TRUST = "minisign-trust/v1"

# Size limits in bytes
MAX_MANIFEST_BYTES = 16 * 1024
MAX_BUNDLE_BYTES = 64 * 1024
MAX_ARTIFACT_SIZE = 2**53 - 1

# Field patterns, always check with .fullmatch()
PACKAGE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
ARTIFACT_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from ..core import jsoncheck
from ..core.constants import HEX64_RE, PACKAGE_RE, PROFILES, SCHEMA_TRUST
from ..core.outcomes import FormatError
from ..crypto.keys import PublicKey, keyid, load_public_pem

@dataclass(frozen=True, slots=True)
class TrustedEntry:
    keyid: str
    public_key: PublicKey
    profile: str
    packages: frozenset[str]

@dataclass(frozen=True, slots=True)
class TrustStore:
    entries: Mapping[str, TrustedEntry]

    def __post_init__(self):
        object.__setattr__(self, "entries", MappingProxyType(dict(self.entries)))

    def find(self, keyid: str) -> TrustedEntry | None:
        return self.entries.get(keyid)

def parse_trust_store(data: bytes) -> TrustStore:
    obj = jsoncheck.expect_object(jsoncheck.loads(data), {"schema": str, "keys": list})
    if obj["schema"] != SCHEMA_TRUST:
        raise FormatError("unknown trust-store schema")
    entries = {}
    for value in obj["keys"]:
        item = jsoncheck.expect_object(value, {
            "keyid": str, "algorithm": str, "public_key_pem": str, "packages": list,
        })
        fingerprint = item["keyid"]
        if not HEX64_RE.fullmatch(fingerprint) or fingerprint in entries:
            raise FormatError("invalid or duplicate trust-store keyid")
        packages = item["packages"]
        if not packages or any(type(p) is not str or not PACKAGE_RE.fullmatch(p) for p in packages):
            raise FormatError("trust packages must be nonempty valid package names")
        if len(set(packages)) != len(packages):
            raise FormatError("duplicate trust-store package")
        if item["algorithm"] not in PROFILES:
            raise FormatError("unsupported trust-store key profile")
        try:
            pem = item["public_key_pem"].encode("ascii")
        except UnicodeEncodeError:
            raise FormatError("public key PEM must be ASCII") from None
        pub, profile = load_public_pem(pem)
        if profile != item["algorithm"] or keyid(pub) != fingerprint:
            raise FormatError("trust-store key profile or fingerprint mismatch")
        entries[fingerprint] = TrustedEntry(fingerprint, pub, profile, frozenset(packages))
    return TrustStore(entries)

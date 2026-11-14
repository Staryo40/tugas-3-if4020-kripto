from dataclasses import dataclass
import json
import os
from pathlib import Path
import tempfile
from types import MappingProxyType
from typing import Mapping

from ..core import jsoncheck
from ..core.constants import HEX64_RE, PACKAGE_RE, PROFILES, SCHEMA_TRUST
from ..core.outcomes import FormatError, InputError
from ..crypto.keys import PublicKey, keyid, load_public_pem, public_pem
from .files import read_bytes

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


def load_trust_store(path, *, create: bool = False) -> TrustStore:
    try:
        with open(path, "rb") as stream:
            data = stream.read()
    except FileNotFoundError:
        if create and not os.path.lexists(path):
            return TrustStore({})
        raise InputError(f"trust store '{path}' does not exist or has a broken link") from None
    except OSError as exc:
        raise InputError(f"cannot read trust store '{path}': {exc.strerror or exc}") from None
    return parse_trust_store(data)


def save_trust_store(path, store: TrustStore) -> None:
    """Validate and atomically replace the store using a sibling temporary file."""
    data = json.dumps({"schema": SCHEMA_TRUST, "keys": [
        {"keyid": entry.keyid, "algorithm": entry.profile,
         "public_key_pem": public_pem(entry.public_key).decode("ascii"),
         "packages": sorted(entry.packages)}
        for entry in sorted(store.entries.values(), key=lambda entry: entry.keyid)
    ]}, indent=2).encode("ascii") + b"\n"
    parse_trust_store(data)
    target = Path(path)
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".tacstmu-trust-", dir=target.parent)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except OSError as exc:
        raise InputError(f"cannot save trust store '{path}': {exc.strerror or exc}") from None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def add_trusted_key(path, key_path, package: str) -> TrustedEntry:
    if not PACKAGE_RE.fullmatch(package):
        raise InputError("invalid trust package name")
    try:
        if Path(path).resolve() == Path(key_path).resolve() or (
            os.path.exists(path) and os.path.samefile(path, key_path)
        ):
            raise InputError("trust store must not overwrite the public key file")
    except OSError as exc:
        raise InputError(f"cannot inspect trust store or public key: {exc.strerror or exc}") from None
    public, profile = load_public_pem(read_bytes(key_path))
    fingerprint = keyid(public)
    store = load_trust_store(path, create=True)
    previous = store.find(fingerprint)
    if previous is not None and package in previous.packages:
        return previous
    packages = (previous.packages if previous is not None else frozenset()) | {package}
    entry = TrustedEntry(fingerprint, public, profile, frozenset(packages))
    entries = dict(store.entries)
    entries[fingerprint] = entry
    save_trust_store(path, TrustStore(entries))
    return entry


def remove_trusted_key(path, fingerprint: str) -> None:
    store = load_trust_store(path)
    if store.find(fingerprint) is None:
        raise InputError(f"keyid '{fingerprint}' is not in the trust store")
    entries = dict(store.entries)
    del entries[fingerprint]
    save_trust_store(path, TrustStore(entries))

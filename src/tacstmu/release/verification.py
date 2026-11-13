from dataclasses import dataclass
from typing import Callable

from ..core import jsoncheck
from ..core.artifact import artifact_name
from ..core.constants import MAX_BUNDLE_BYTES, PROFILES
from ..core.outcomes import (
    ArtifactMismatchError, InputError, InvalidSignatureError, KeyNotTrustedError,
    MetadataMismatchError, STATUS_OK, TacstmuError, UnsupportedAlgorithmError,
)
from ..crypto import signature
from . import bundle, manifest
from .files import read_bytes, snapshot
from .trust import TrustStore, parse_trust_store

@dataclass(frozen=True, slots=True)
class VerifiedArtifact:
    manifest: dict
    sha256: str
    content: bytes | None

def failed_result() -> dict:
    return {"valid": False, "status": InputError.status, "message": "verification not completed",
            "algorithm": None, "keyid": None, "package": None, "version": None}


def verify_details(file, bundle_path, trust_store, package: str, version: str, *,
                   capture: bool = False,
                   trust_parser: Callable[[bytes], TrustStore] = parse_trust_store
                   ) -> tuple[dict, VerifiedArtifact | None]:
    result = failed_result()
    try:
        raw_bundle = read_bytes(bundle_path, MAX_BUNDLE_BYTES)
        raw_trust = read_bytes(trust_store)
        size, digest, content = snapshot(file, capture)
        message, signed = bundle.parse(raw_bundle)
        from ..core.constants import MAX_MANIFEST_BYTES
        if len(message) <= MAX_MANIFEST_BYTES:
            decoded = jsoncheck.loads(message)
            if type(decoded) is dict:
                for name in ("algorithm", "keyid", "package", "version"):
                    if type(decoded.get(name)) is str:
                        result[name] = decoded[name]
        obj = manifest.parse(message)
        store = trust_parser(raw_trust)
        profile = obj["algorithm"]
        if profile not in PROFILES:
            raise UnsupportedAlgorithmError("unsupported manifest algorithm")
        entry = store.find(obj["keyid"])
        if entry is None or entry.profile != profile or package not in entry.packages:
            raise KeyNotTrustedError("key is absent, has a different profile, or is unauthorized for expected package")
        if not signature.verify(profile, entry.public_key, message, signed):
            raise InvalidSignatureError("manifest signature is invalid")
        if obj["package"] != package or obj["version"] != version or obj["artifact"]["name"] != artifact_name(file):
            raise MetadataMismatchError("package, version, or artifact basename does not match")
        if obj["artifact"]["size"] != size or obj["artifact"]["sha256"] != digest:
            raise ArtifactMismatchError("artifact size or SHA-256 does not match")
        result.update(valid=True, status=STATUS_OK, message="Signature, metadata, and artifact are valid.")
        return result, VerifiedArtifact(obj, digest, content)
    except TacstmuError as exc:
        result.update(status=exc.status, message=str(exc))
        return result, None

def verify_release(file, bundle_path, trust_store, package: str, version: str, *,
                   trust_parser: Callable[[bytes], TrustStore] = parse_trust_store) -> dict:
    return verify_details(file, bundle_path, trust_store, package, version,
                          trust_parser=trust_parser)[0]

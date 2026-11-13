import json

from ..core import jsoncheck
from ..core.constants import (
    ARTIFACT_NAME_RE, HEX64_RE, MAX_ARTIFACT_SIZE, MAX_MANIFEST_BYTES,
    PACKAGE_RE, SCHEMA_MANIFEST, VERSION_RE,
)
from ..core.outcomes import FormatError

FIELDS = {"schema": str, "package": str, "version": str, "algorithm": str,
          "keyid": str, "artifact": dict}
ARTIFACT_FIELDS = {"name": str, "size": int, "sha256": str}

def validate(value: object) -> dict:
    obj = jsoncheck.expect_object(value, FIELDS)
    artifact = jsoncheck.expect_object(obj["artifact"], ARTIFACT_FIELDS)
    if obj["schema"] != SCHEMA_MANIFEST:
        raise FormatError("unknown manifest schema")
    for name, pattern in (("package", PACKAGE_RE), ("version", VERSION_RE), ("keyid", HEX64_RE)):
        if not pattern.fullmatch(obj[name]):
            raise FormatError(f"invalid manifest {name}")
    # Membership is deliberately checked at verification stage 3.
    if any(ord(char) < 32 or ord(char) > 126 or char in '\\"' for char in obj["algorithm"]):
        raise FormatError("manifest algorithm must use directly written printable ASCII")
    if not ARTIFACT_NAME_RE.fullmatch(artifact["name"]):
        raise FormatError("invalid manifest artifact name")
    if not HEX64_RE.fullmatch(artifact["sha256"]):
        raise FormatError("invalid manifest artifact SHA-256")
    if not 0 <= artifact["size"] <= MAX_ARTIFACT_SIZE:
        raise FormatError("manifest artifact size is out of range")
    return obj

def serialize(value: object) -> bytes:
    obj = validate(value)
    ordered = {name: obj[name] for name in FIELDS}
    ordered["artifact"] = {name: obj["artifact"][name] for name in ARTIFACT_FIELDS}
    data = json.dumps(ordered, ensure_ascii=False, separators=(",", ":")).encode("ascii")
    if len(data) > MAX_MANIFEST_BYTES:
        raise FormatError("manifest exceeds 16 KiB")
    return data

def parse(data: bytes) -> dict:
    if len(data) > MAX_MANIFEST_BYTES:
        raise FormatError("manifest exceeds 16 KiB")
    obj = validate(jsoncheck.loads(data))
    if serialize(obj) != data:
        raise FormatError("manifest is not canonically serialized")
    return obj

def build(package: str, version: str, algorithm: str, keyid: str,
          name: str, size: int, sha256: str) -> bytes:
    return serialize({"schema": SCHEMA_MANIFEST, "package": package, "version": version,
                      "algorithm": algorithm, "keyid": keyid,
                      "artifact": {"name": name, "size": size, "sha256": sha256}})

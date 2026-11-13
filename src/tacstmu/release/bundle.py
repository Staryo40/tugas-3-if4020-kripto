import json

from ..core import base64 as b64, jsoncheck
from ..core.constants import MAX_BUNDLE_BYTES, SCHEMA_BUNDLE
from ..core.outcomes import FormatError

def parse(data: bytes) -> tuple[bytes, bytes]:
    if len(data) > MAX_BUNDLE_BYTES:
        raise FormatError("bundle exceeds 64 KiB")
    obj = jsoncheck.expect_object(jsoncheck.loads(data), {
        "schema": str, "manifest_b64": str, "signature_b64": str,
    })
    if obj["schema"] != SCHEMA_BUNDLE:
        raise FormatError("unknown bundle schema")
    return b64.decode_strict(obj["manifest_b64"]), b64.decode_strict(obj["signature_b64"])

def serialize(manifest: bytes, signature: bytes) -> bytes:
    data = json.dumps({"schema": SCHEMA_BUNDLE, "manifest_b64": b64.encode(manifest),
                       "signature_b64": b64.encode(signature)}, separators=(",", ":")).encode("ascii")
    if len(data) > MAX_BUNDLE_BYTES:
        raise FormatError("bundle exceeds 64 KiB")
    return data

import json

import pytest

from tacstmu.core.constants import MAX_ARTIFACT_SIZE, MAX_BUNDLE_BYTES, MAX_MANIFEST_BYTES
from tacstmu.core.outcomes import FormatError
from tacstmu.release import bundle, manifest

@pytest.fixture
def manifest_object():
    return {"schema": "minisign-manifest/v1", "package": "app", "version": "1.0",
            "algorithm": "ed25519", "keyid": "a" * 64,
            "artifact": {"name": "app.bin", "size": 3, "sha256": "b" * 64}}

def test_manifest_exact_golden_bytes(manifest_object):
    expected = (b'{"schema":"minisign-manifest/v1","package":"app","version":"1.0",'
                b'"algorithm":"ed25519","keyid":"' + b'a' * 64 +
                b'","artifact":{"name":"app.bin","size":3,"sha256":"' + b'b' * 64 + b'"}}')
    obj = dict(reversed(list(manifest_object.items())))
    obj["artifact"] = dict(reversed(list(obj["artifact"].items())))
    assert manifest.serialize(obj) == expected
    assert manifest.parse(expected) == manifest_object

@pytest.mark.parametrize("size", [0, MAX_ARTIFACT_SIZE])
def test_manifest_integer_boundaries(manifest_object, size):
    manifest_object["artifact"]["size"] = size
    assert manifest.parse(manifest.serialize(manifest_object))["artifact"]["size"] == size

@pytest.mark.parametrize("field,value", [
    ("schema", "wrong"), ("package", "App"), ("package", "a" * 65),
    ("version", "bad version"), ("keyid", "A" * 64), ("keyid", "a" * 63),
    ("algorithm", "é"), ("algorithm", "bad\nprofile"),
    ("package", None), ("version", 1), ("artifact", []),
])
def test_manifest_invalid_outer_values(manifest_object, field, value):
    manifest_object[field] = value
    with pytest.raises(FormatError):
        manifest.serialize(manifest_object)

@pytest.mark.parametrize("field,value", [
    ("name", "../app.bin"), ("name", "a" * 129), ("name", "é.bin"),
    ("sha256", "G" * 64), ("size", -1), ("size", MAX_ARTIFACT_SIZE + 1),
    ("size", True), ("size", 3.0), ("size", None),
])
def test_manifest_invalid_artifact_values(manifest_object, field, value):
    manifest_object["artifact"][field] = value
    with pytest.raises(FormatError):
        manifest.serialize(manifest_object)

@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_manifest_exact_field_sets(manifest_object, nested, mutation):
    obj = manifest_object["artifact"] if nested else manifest_object
    if mutation == "missing":
        obj.pop(next(iter(obj)))
    else:
        obj["extra"] = "unexpected"
    with pytest.raises(FormatError):
        manifest.serialize(manifest_object)

@pytest.mark.parametrize("mutation", ["newline", "spaces", "order", "nested-order", "escape", "float", "exponent", "bom", "duplicate", "nested-duplicate"])
def test_noncanonical_or_ambiguous_manifest_rejected(manifest_object, mutation):
    data = manifest.serialize(manifest_object)
    if mutation == "newline":
        data += b"\n"
    elif mutation == "spaces":
        data = json.dumps(manifest_object, indent=2).encode()
    elif mutation == "order":
        data = json.dumps(dict(reversed(list(manifest_object.items()))), separators=(",", ":")).encode()
    elif mutation == "nested-order":
        manifest_object["artifact"] = dict(reversed(list(manifest_object["artifact"].items())))
        data = json.dumps(manifest_object, separators=(",", ":")).encode()
    elif mutation == "escape":
        data = data.replace(b'"app"', b'"\\u0061pp"')
    elif mutation in ("float", "exponent"):
        data = data.replace(b'"size":3', b'"size":3.0' if mutation == "float" else b'"size":3e0')
    elif mutation == "bom":
        data = b"\xef\xbb\xbf" + data
    elif mutation == "duplicate":
        data = data.replace(b'"package":"app"', b'"package":"app","package":"app"')
    else:
        data = data.replace(b'"size":3', b'"size":3,"size":3')
    with pytest.raises(FormatError):
        manifest.parse(data)

def test_unknown_manifest_profile_is_not_a_format_error(manifest_object):
    manifest_object["algorithm"] = "unknown-profile"
    assert manifest.parse(manifest.serialize(manifest_object))["algorithm"] == "unknown-profile"

def test_manifest_16k_limit(manifest_object):
    data = manifest.serialize(manifest_object)
    manifest_object["algorithm"] = "x" * (MAX_MANIFEST_BYTES - len(data) + len("ed25519"))
    at_limit = manifest.serialize(manifest_object)
    assert len(at_limit) == MAX_MANIFEST_BYTES
    assert manifest.parse(at_limit)["algorithm"] == manifest_object["algorithm"]
    with pytest.raises(FormatError):
        manifest.parse(at_limit + b" ")
    manifest_object["algorithm"] += "x"
    with pytest.raises(FormatError):
        manifest.serialize(manifest_object)

def test_bundle_roundtrip_does_not_reserialize_manifest():
    message, signed = b'noncanonical manifest bytes\n', bytes(range(64))
    assert bundle.parse(bundle.serialize(message, signed)) == (message, signed)

def test_bundle_whitespace_order_and_size_boundary():
    obj = json.loads(bundle.serialize(b"M", b"signature"))
    data = json.dumps(dict(reversed(list(obj.items()))), indent=2).encode()
    padded = data + b" " * (MAX_BUNDLE_BYTES - len(data))
    assert bundle.parse(padded) == (b"M", b"signature")
    with pytest.raises(FormatError):
        bundle.parse(padded + b" ")
    with pytest.raises(FormatError):
        bundle.serialize(b"x" * MAX_BUNDLE_BYTES, b"s")

@pytest.mark.parametrize("field", ["manifest_b64", "signature_b64"])
@pytest.mark.parametrize("value", ["!===", "YQ", "YQ===", "YQ==\n", "YR==", "____", None, 1])
def test_bundle_strict_base64_and_types(field, value):
    obj = json.loads(bundle.serialize(b"M", b"S"))
    obj[field] = value
    with pytest.raises(FormatError):
        bundle.parse(json.dumps(obj).encode())

@pytest.mark.parametrize("mutation", ["extra", "missing", "schema", "duplicate", "bom", "utf8", "array"])
def test_bundle_invalid_structure(mutation):
    obj = json.loads(bundle.serialize(b"M", b"S"))
    if mutation == "extra":
        obj["extra"] = 1
    elif mutation == "missing":
        del obj["signature_b64"]
    elif mutation == "schema":
        obj["schema"] = "wrong"
    data = json.dumps(obj).encode()
    if mutation == "duplicate":
        data = data.replace(b'"signature_b64": "Uw=="', b'"signature_b64":"Uw==","signature_b64":"Uw=="')
    elif mutation == "bom":
        data = b"\xef\xbb\xbf" + data
    elif mutation == "utf8":
        data = b"\xff"
    elif mutation == "array":
        data = b"[]"
    with pytest.raises(FormatError):
        bundle.parse(data)

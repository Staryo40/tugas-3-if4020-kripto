import pytest

from tacstmu.core.jsoncheck import expect_object, loads
from tacstmu.core.outcomes import FormatError

BUNDLE_SHAPE = {"schema": str, "manifest_b64": str, "signature_b64": str}


# loads
def test_loads_valid_object():
    assert loads(b'{"a":1,"b":{"c":[true,null,"x"]}}') == {"a": 1, "b": {"c": [True, None, "x"]}}

@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b'{"a":1,"a":2}', id="duplicate-top-level"),
        pytest.param(b'{"outer":{"k":1,"k":1}}', id="duplicate-nested"),
        pytest.param(b'\xef\xbb\xbf{"a":1}', id="bom"),
        pytest.param(b'{"a":"\xff"}', id="invalid-utf8"),
        pytest.param(b'{"a":NaN}', id="nan"),
        pytest.param(b'{"a":1} x', id="syntax-error"),
        pytest.param(b"[" * 100_000 + b"]" * 100_000, id="deep-nesting"),
    ],
)
def test_loads_rejects(data):
    with pytest.raises(FormatError):
        loads(data)

def test_duplicate_message_names_field():
    with pytest.raises(FormatError, match="version"):
        loads(b'{"version":"1.0.0","version":"9.9.9"}')


# expect_object
def test_expect_object_valid():
    obj = {"schema": "s", "manifest_b64": "m", "signature_b64": "g"}
    assert expect_object(obj, BUNDLE_SHAPE) is obj

@pytest.mark.parametrize(
    "value, match",
    [
        pytest.param(["not", "object"], "object", id="not-object"),
        pytest.param({"schema": "s", "manifest_b64": "m"}, "signature_b64", id="missing"),
        pytest.param(
            {"schema": "s", "manifest_b64": "m", "signature_b64": "g", "key": "x"}, "key", id="extra"
        ),
        pytest.param({"schema": None, "manifest_b64": "m", "signature_b64": "g"}, "null", id="null"),
        pytest.param({"schema": 1, "manifest_b64": "m", "signature_b64": "g"}, "integer", id="wrong-type"),
    ],
)
def test_expect_object_rejects(value, match):
    with pytest.raises(FormatError, match=match):
        expect_object(value, BUNDLE_SHAPE)

def test_bool_is_not_integer():
    with pytest.raises(FormatError, match="boolean"):
        expect_object({"size": True}, {"size": int})

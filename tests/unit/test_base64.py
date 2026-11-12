import os

import pytest

from tacstmu.core.base64 import decode_strict, encode
from tacstmu.core.outcomes import FormatError


# Round trips
@pytest.mark.parametrize("length", [0, 1, 2, 3])
def test_round_trip(length):
    data = os.urandom(length)
    assert decode_strict(encode(data)) == data

def test_known_values():
    assert encode(b"A") == "QQ=="
    assert encode(b"\xfb\xff") == "+/8="


# Rejected encodings
@pytest.mark.parametrize(
    "text",
    [
        pytest.param("QUJD\n", id="whitespace"),
        pytest.param("-_8=", id="url-safe-alphabet"),
        pytest.param("QQ", id="missing-padding"),
        pytest.param("QQ===", id="extra-padding"),
        pytest.param("QQ==QQ==", id="padding-in-middle"),
        pytest.param("QUJé", id="non-ascii"),
    ],
)
def test_rejects(text):
    with pytest.raises(FormatError):
        decode_strict(text)

def test_rejects_non_canonical_padding_bits():
    with pytest.raises(FormatError, match="canonical"):
        decode_strict("QR==")

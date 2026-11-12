import os

import pytest

from tacstmu.core.base64 import decode_strict, encode
from tacstmu.core.outcomes import FormatError


# Round trips
@pytest.mark.parametrize("length", [0, 1, 2, 3, 4, 32, 64, 384, 1000])
def test_round_trip(length):
    data = os.urandom(length)
    assert decode_strict(encode(data)) == data

def test_known_values():
    assert encode(b"") == ""
    assert encode(b"A") == "QQ=="
    assert encode(b"AB") == "QUI="
    assert encode(b"ABC") == "QUJD"
    assert decode_strict("QQ==") == b"A"

def test_uses_standard_alphabet():
    assert encode(b"\xfb\xff") == "+/8="


# Rejected encodings
@pytest.mark.parametrize(
    "text",
    [
        pytest.param("QUJD\n", id="trailing-newline"),
        pytest.param("QU JD", id="inner-space"),
        pytest.param(" QUJD", id="leading-space"),
        pytest.param("QUJD\r\nQUJD", id="line-break"),
        pytest.param("-_8=", id="url-safe-alphabet"),
        pytest.param("QQ", id="missing-padding"),
        pytest.param("QUI", id="missing-single-padding"),
        pytest.param("QQ===", id="extra-padding"),
        pytest.param("QQ==QQ==", id="padding-in-middle"),
        pytest.param("=QUJ", id="padding-at-start"),
        pytest.param("QUJé", id="non-ascii"),
        pytest.param("Q", id="single-char"),
    ],
)
def test_rejects(text):
    with pytest.raises(FormatError):
        decode_strict(text)


# Canonical form
@pytest.mark.parametrize("text", ["QR==", "QUJ=", "QUK="])
def test_rejects_non_canonical_padding_bits(text):
    with pytest.raises(FormatError, match="canonical"):
        decode_strict(text)

import base64
import binascii
import re

from .outcomes import FormatError

_ALPHABET_RE = re.compile(r"[A-Za-z0-9+/]*={0,2}")

def encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def decode_strict(text: str) -> bytes:
    _require_alphabet(text)
    _require_padded_length(text)

    try:
        data = base64.b64decode(text, validate=True)
    except binascii.Error:
        raise FormatError("invalid Base64: malformed encoding") from None

    _require_canonical(text, data)

    return data


# Encoding checks, used by decode_strict
def _require_alphabet(text: str) -> None:
    if not _ALPHABET_RE.fullmatch(text):
        raise FormatError("invalid Base64: only A-Z, a-z, 0-9, +, / and trailing = padding are allowed")

def _require_padded_length(text: str) -> None:
    if len(text) % 4 != 0:
        raise FormatError("invalid Base64: length must be a multiple of 4 (missing or extra padding)")

def _require_canonical(text: str, data: bytes) -> None:
    # unused low bits in the last character must be zero
    if encode(data) != text:
        raise FormatError("invalid Base64: not in canonical form")

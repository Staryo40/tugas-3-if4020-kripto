import json

from .outcomes import FormatError

_UTF8_BOM = b"\xef\xbb\xbf"

def loads(data: bytes) -> object:
    _reject_bom(data)
    text = _decode_utf8(data)

    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
    except json.JSONDecodeError as exc:
        raise FormatError(f"invalid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}") from None
    except RecursionError:
        raise FormatError("invalid JSON: nested too deeply") from None


def expect_object(value: object, fields: dict[str, type]) -> dict:
    obj = _require_dict(value)
    _require_exact_keys(obj, fields)
    _require_types(obj, fields)

    return obj


# Parsing checks, used by loads
def _reject_bom(data: bytes) -> None:
    if data.startswith(_UTF8_BOM):
        raise FormatError("invalid JSON: byte order mark is not allowed")

def _decode_utf8(data: bytes) -> str:
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise FormatError("invalid JSON: not valid UTF-8") from None

def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    obj: dict = {}

    for key, value in pairs:
        if key in obj:
            raise FormatError(f"invalid JSON: duplicate field '{key}'")
        obj[key] = value
    
    return obj

def _reject_non_finite(name: str) -> None:
    raise FormatError(f"invalid JSON: '{name}' is not allowed")


# Shape checks, used by expect_object
def _require_dict(value: object) -> dict:
    if type(value) is not dict:
        raise FormatError(f"expected a JSON object, got {_json_type_name(value)}")
    
    return value

def _require_exact_keys(obj: dict, fields: dict[str, type]) -> None:
    missing = [name for name in fields if name not in obj]
    if missing:
        raise FormatError(f"missing field(s): {', '.join(missing)}")
    extra = [name for name in obj if name not in fields]

    if extra:
        raise FormatError(f"unexpected field(s): {', '.join(extra)}")

def _require_types(obj: dict, fields: dict[str, type]) -> None:
    for name, expected in fields.items():
        # exact match: bool is a subclass of int in Python
        if type(obj[name]) is not expected:
            raise FormatError(
                f"field '{name}' must be {_type_name(expected)}, got {_json_type_name(obj[name])}"
            )


# JSON type names for error messages
_JSON_TYPE_NAMES = {
    dict: "object",
    list: "array",
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
    type(None): "null",
}

def _type_name(t: type) -> str:
    return _JSON_TYPE_NAMES.get(t, t.__name__)

def _json_type_name(value: object) -> str:
    return _type_name(type(value))

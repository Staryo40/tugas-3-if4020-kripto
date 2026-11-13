import copy
import json
from dataclasses import FrozenInstanceError

import pytest

from tacstmu.core.constants import PROFILES
from tacstmu.core.outcomes import FormatError
from tacstmu.release.trust import TrustStore, parse_trust_store

@pytest.mark.parametrize("profile", PROFILES)
def test_valid_entry_lookup_and_empty_store(make_release, profile):
    case = make_release(profile)
    store = parse_trust_store(case.trust.read_bytes())
    entry = store.find(case.keyid)
    assert entry.keyid == case.keyid and entry.profile == profile
    assert entry.packages == frozenset({"app", "app-sbom"})
    assert store.find("f" * 64) is None
    empty = parse_trust_store(b'{"schema":"minisign-trust/v1","keys":[]}')
    assert empty.find(case.keyid) is None

def test_store_defensively_copies_and_exposes_immutable_entries(make_release):
    case = make_release()
    parsed = parse_trust_store(case.trust.read_bytes())
    source = dict(parsed.entries)
    store = TrustStore(source)
    source.clear()
    assert store.find(case.keyid) is not None
    with pytest.raises(TypeError):
        store.entries["other"] = store.find(case.keyid)
    with pytest.raises(FrozenInstanceError):
        store.find(case.keyid).profile = "other"

@pytest.mark.parametrize("mutation", [
    "duplicate-key", "empty-packages", "duplicate-package", "wildcard", "wrong-package-type",
    "bad-package", "bad-pem", "nonascii-pem", "fingerprint", "profile-mismatch", "unknown-profile",
    "extra-entry-field", "missing-entry-field", "null-entry", "extra-store-field", "wrong-schema",
    "keys-not-array", "duplicate-json-field",
])
def test_entire_read_only_trust_contract(make_release, mutation):
    case = make_release()
    obj = copy.deepcopy(case.trust_object)
    item = obj["keys"][0]
    if mutation == "duplicate-key":
        obj["keys"].append(copy.deepcopy(item))
    elif mutation == "empty-packages":
        item["packages"] = []
    elif mutation == "duplicate-package":
        item["packages"] = ["app", "app"]
    elif mutation == "wildcard":
        item["packages"] = ["*"]
    elif mutation == "wrong-package-type":
        item["packages"] = [None]
    elif mutation == "bad-package":
        item["packages"] = ["App"]
    elif mutation == "bad-pem":
        item["public_key_pem"] = "not PEM"
    elif mutation == "nonascii-pem":
        item["public_key_pem"] = "é"
    elif mutation == "fingerprint":
        item["keyid"] = "0" * 64
    elif mutation == "profile-mismatch":
        item["algorithm"] = "rsa-pss-sha256"
    elif mutation == "unknown-profile":
        item["algorithm"] = "unknown"
    elif mutation == "extra-entry-field":
        item["extra"] = True
    elif mutation == "missing-entry-field":
        del item["public_key_pem"]
    elif mutation == "null-entry":
        obj["keys"] = [None]
    elif mutation == "extra-store-field":
        obj["extra"] = True
    elif mutation == "wrong-schema":
        obj["schema"] = "wrong"
    elif mutation == "keys-not-array":
        obj["keys"] = {}
    data = json.dumps(obj).encode()
    if mutation == "duplicate-json-field":
        data = data.replace(b'"keys":', b'"keys":[],"keys":')
    with pytest.raises(FormatError):
        parse_trust_store(data)

def test_parser_injection_uses_same_bytes_and_propagates_format_status(make_release):
    case = make_release()
    received = []
    def parser(data):
        received.append(data)
        raise FormatError("Person 3 parser rejected store")
    assert case.verify(trust_parser=parser)["status"] == "FORMAT_ERROR"
    assert received == [case.trust.read_bytes()]
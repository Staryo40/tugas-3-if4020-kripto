import hashlib
import json
from types import SimpleNamespace

import pytest

from tacstmu.core.constants import PROFILES
from tacstmu.crypto import keys, signature
from tacstmu.release import bundle, manifest
from tacstmu.release.signing import sign_release
from tacstmu.release.verification import verify_release

@pytest.fixture(scope="session")
def signing_keys():
    return {profile: keys.generate(profile) for profile in PROFILES}

@pytest.fixture
def make_release(tmp_path, signing_keys):
    count = 0

    def make(profile="ed25519", content=b"release\x00\xff", package="app", version="1.0"):
        nonlocal count
        count += 1
        folder = tmp_path / str(count)
        folder.mkdir()
        file, key, output, trust = (folder / n for n in (
            "app.bin", "test.key.pem", "bundle.json", "trust.json"))
        private = signing_keys[profile]
        public = private.public_key()
        fingerprint = keys.keyid(public)
        file.write_bytes(content)
        key.write_bytes(keys.private_pem(private))
        trust_object = {"schema": "minisign-trust/v1", "keys": [{
            "keyid": fingerprint, "algorithm": profile,
            "public_key_pem": keys.public_pem(public).decode("ascii"),
            "packages": list(dict.fromkeys([package, "app-sbom"]))}]}
        trust.write_text(json.dumps(trust_object), encoding="utf-8")
        sign_release(file, package, version, key, output)
        case = SimpleNamespace(file=file, key=key, output=output, trust=trust, profile=profile,
                               package=package, version=version, private=private,
                               public=public, keyid=fingerprint, trust_object=trust_object,
                               content=content, digest=hashlib.sha256(content).hexdigest())
        case.verify = lambda **kw: verify_release(
            kw.get("file", file), output, trust, kw.get("package", package), kw.get("version", version),
            **({"trust_parser": kw["trust_parser"]} if "trust_parser" in kw else {}))
        case.message, case.signed = bundle.parse(output.read_bytes())
        case.manifest = manifest.parse(case.message)

        def write_message(message, resign=False):
            signed = signature.sign(profile, private, message) if resign else case.signed
            output.write_bytes(bundle.serialize(message, signed))
        case.write_message = write_message
        case.save_trust = lambda: trust.write_text(json.dumps(trust_object), encoding="utf-8")
        return case
    return make

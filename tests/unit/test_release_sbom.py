import json
import subprocess
import sys

import pytest

from tacstmu import cli
from tacstmu.core.constants import PROFILES
from tacstmu.core.outcomes import FormatError
from tacstmu.release import bundle, sbom
from tacstmu.release.signing import sign_release

@pytest.fixture
def sbom_object():
    return {"schema": "tacstmu-sbom/v1", "release": {"sha256": "a" * 64},
            "components": [{"name": "library", "version": "1"}]}

@pytest.fixture
def make_pair(make_release):
    def make(profile="ed25519", sbom_profile=None):
        release = make_release(profile)
        value = {"schema": "tacstmu-sbom/v1", "release": {"sha256": release.digest},
                 "components": [{"name": "app", "version": release.version}]}
        document = make_release(sbom_profile or profile, json.dumps(value).encode(), package="app-sbom")
        if document.keyid != release.keyid:
            release.trust_object["keys"].append(document.trust_object["keys"][0])
        release.save_trust()
        def verify():
            return sbom.verify_release_with_sbom(release.file, release.output, document.file, document.output,
                release.trust, release.package, release.version, document.package, document.version)
        return release, document, verify
    return make

@pytest.mark.parametrize("profile", PROFILES)
def test_SBOM01_signed_pair_passes_all_profiles(make_pair, profile):
    _, _, verify = make_pair(profile)
    result = verify()
    assert result["valid"] is True and result["status"] == "OK"
    assert result["binding_valid"] is True and result["stage"] == "complete"
    assert result["release"]["valid"] is True and result["sbom"]["valid"] is True

def test_SBOM02_different_trusted_signers_allowed(make_pair):
    _, _, verify = make_pair("ed25519", "ecdsa-p256-sha256")
    assert verify()["valid"] is True

@pytest.mark.parametrize("mutation,status,stage", [
    pytest.param("sbom-content", "ARTIFACT_MISMATCH", "sbom", id="SBOM03_modified_content"),
    pytest.param("release-content", "ARTIFACT_MISMATCH", "release", id="SBOM04_replaced_release"),
    pytest.param("resigned-release", "SBOM_BINDING_MISMATCH", "binding", id="SBOM05_validly_resigned_substitute"),
    pytest.param("resigned-wrong-reference", "SBOM_BINDING_MISMATCH", "binding", id="SBOM06_signed_wrong_reference"),
    pytest.param("resigned-malformed-sbom", "FORMAT_ERROR", "binding", id="SBOM07_signed_invalid_schema"),
    pytest.param("sbom-signature", "INVALID_SIGNATURE", "sbom", id="SBOM08_invalid_sbom_signature"),
    pytest.param("release-signature", "INVALID_SIGNATURE", "release", id="SBOM09_invalid_release_signature"),
    pytest.param("unauthorized-sbom", "KEY_NOT_TRUSTED", "sbom", id="SBOM10_unauthorized_sbom_signer"),
    pytest.param("missing-release", "INPUT_ERROR", "release", id="SBOM11_missing_release"),
])
def test_combined_rejections(make_pair, mutation, status, stage):
    release, document, verify = make_pair()
    if mutation == "sbom-content":
        document.file.write_bytes(document.content + b" ")
    elif mutation in ("release-content", "resigned-release"):
        release.file.write_bytes(b"replacement release")
        if mutation == "resigned-release":
            sign_release(release.file, release.package, release.version, release.key, release.output, force=True)
    elif mutation in ("resigned-wrong-reference", "resigned-malformed-sbom"):
        obj = json.loads(document.content)
        if mutation == "resigned-wrong-reference":
            obj["release"]["sha256"] = "0" * 64
        else:
            del obj["release"]
        document.file.write_text(json.dumps(obj))
        sign_release(document.file, document.package, document.version, document.key, document.output, force=True)
    elif mutation in ("sbom-signature", "release-signature"):
        case = document if mutation == "sbom-signature" else release
        case.output.write_bytes(bundle.serialize(case.message, b"\x00" * 64))
    elif mutation == "unauthorized-sbom":
        release.trust_object["keys"][0]["packages"] = [release.package]
        release.save_trust()
    else:
        release.file.unlink()
    result = verify()
    assert result["status"] == status and result["stage"] == stage
    assert result["valid"] is False and result["binding_valid"] is False
    if stage == "release":
        assert result["sbom"] is None

def test_SBOM12_binding_uses_authenticated_snapshot(make_pair, monkeypatch):
    release, document, verify = make_pair()
    original = sbom.verify_details
    def replace_after_verified(*args, **kwargs):
        result = original(*args, **kwargs)
        if kwargs.get("capture"):
            document.file.write_bytes(b"now invalid JSON")
        return result
    monkeypatch.setattr(sbom, "verify_details", replace_after_verified)
    assert verify()["valid"] is True
    assert document.file.read_bytes() == b"now invalid JSON"

@pytest.mark.parametrize("mutation", ["schema", "missing-reference", "uppercase-hash", "short-hash", "extra-release", "empty-name", "null-version", "extra-component", "wrong-components", "duplicate", "bom"])
def test_strict_sbom_schema(sbom_object, mutation):
    obj = sbom_object
    if mutation == "schema":
        obj["schema"] = "wrong"
    elif mutation == "missing-reference":
        del obj["release"]["sha256"]
    elif mutation == "uppercase-hash":
        obj["release"]["sha256"] = "A" * 64
    elif mutation == "short-hash":
        obj["release"]["sha256"] = "a" * 63
    elif mutation == "extra-release":
        obj["release"]["extra"] = True
    elif mutation == "empty-name":
        obj["components"][0]["name"] = ""
    elif mutation == "null-version":
        obj["components"][0]["version"] = None
    elif mutation == "extra-component":
        obj["components"][0]["extra"] = True
    elif mutation == "wrong-components":
        obj["components"] = {}
    data = json.dumps(obj).encode()
    if mutation == "duplicate":
        data = data.replace(b'"components":', b'"components":[],"components":')
    elif mutation == "bom":
        data = b"\xef\xbb\xbf" + data
    with pytest.raises(FormatError):
        sbom.parse_sbom(data)

def test_sbom_accepts_empty_components_and_unicode_component_names(sbom_object):
    sbom_object["components"] = []
    assert sbom.parse_sbom(json.dumps(sbom_object).encode()) == sbom_object
    sbom_object["components"] = [{"name": "pustaka-é", "version": "1"}]
    assert sbom.parse_sbom(json.dumps(sbom_object, ensure_ascii=False).encode()) == sbom_object

@pytest.mark.parametrize("fault,code,status", [(None, 0, "OK"), ("binding", 1, "SBOM_BINDING_MISMATCH"), ("input", 2, "INPUT_ERROR")])
def test_combined_cli_codes_and_json(make_pair, capsys, fault, code, status):
    release, document, _ = make_pair()
    if fault == "binding":
        release.file.write_bytes(b"new release")
        sign_release(release.file, release.package, release.version, release.key, release.output, force=True)
    elif fault == "input":
        release.file.unlink()
    argv = ["verify-release", "--file", str(release.file), "--bundle", str(release.output),
            "--sbom", str(document.file), "--sbom-bundle", str(document.output),
            "--trust-store", str(release.trust), "--package", release.package, "--version", release.version,
            "--sbom-package", document.package, "--sbom-version", document.version, "--json"]
    assert cli.main(argv) == code
    text = capsys.readouterr().out
    assert text.count("\n") == 1
    assert json.loads(text)["status"] == status

def test_combined_usage_error_is_json_input_error(capsys):
    assert cli.main(["verify-release", "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "INPUT_ERROR" and result["stage"] == "input"


def test_SBOM13_large_integer_content_is_format_error(make_pair):
    release, document, _ = make_pair()
    document.file.write_bytes(b'{"schema":"tacstmu-sbom/v1","release":{"sha256":' +
                              b"9" * 5000 + b'},"components":[]}')
    sign_release(document.file, document.package, document.version, document.key, document.output, force=True)
    argv = ["verify-release", "--file", str(release.file), "--bundle", str(release.output),
            "--sbom", str(document.file), "--sbom-bundle", str(document.output),
            "--trust-store", str(release.trust), "--package", release.package, "--version", release.version,
            "--sbom-package", document.package, "--sbom-version", document.version, "--json"]
    run = subprocess.run([sys.executable, "-X", "int_max_str_digits=4300", "-m", "tacstmu", *argv],
                         capture_output=True, text=True)
    assert run.returncode == 1
    result = json.loads(run.stdout)
    assert result["status"] == "FORMAT_ERROR" and result["stage"] == "binding"
    assert result["release"]["valid"] is True and result["sbom"]["valid"] is True
    assert result["valid"] is False and result["binding_valid"] is False
    assert run.stdout.count("\n") == 1

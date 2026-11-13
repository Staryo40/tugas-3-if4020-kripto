import json
import os
import subprocess
import sys

import pytest

from tacstmu import cli
from tacstmu.core.constants import MAX_MANIFEST_BYTES, PROFILES
from tacstmu.core.outcomes import InputError
from tacstmu.crypto import signature
from tacstmu.release import bundle, files, manifest
from tacstmu.release.signing import sign_release
from tacstmu.release.verification import verify_details

def verify_args(case):
    return ["verify", "--file", str(case.file), "--bundle", str(case.output),
            "--trust-store", str(case.trust), "--package", case.package,
            "--version", case.version, "--json"]

@pytest.mark.parametrize("profile", PROFILES)
def test_sign_and_verify_real_crypto(make_release, profile):
    case = make_release(profile)
    assert case.manifest["algorithm"] == profile
    assert case.manifest["keyid"] == case.keyid
    assert case.manifest["artifact"] == {"name": "app.bin", "size": len(case.content), "sha256": case.digest}
    assert signature.verify(profile, case.public, case.message, case.signed)
    result = case.verify()
    assert result == {"valid": True, "status": "OK", "message": result["message"],
                      "algorithm": profile, "keyid": case.keyid, "package": "app", "version": "1.0"}
    assert result["message"]
    assert case.file.read_bytes() == case.content

def test_sign_passes_canonical_manifest_bytes_to_crypto(make_release, monkeypatch):
    case = make_release()
    original = signature.sign
    received = []
    def recording_sign(profile, key, message):
        received.append(message)
        return original(profile, key, message)
    monkeypatch.setattr(signature, "sign", recording_sign)
    sign_release(case.file, case.package, case.version, case.key, case.output, force=True)
    stored, _ = bundle.parse(case.output.read_bytes())
    assert received == [stored]
    assert manifest.parse(stored) == case.manifest

def test_verify_passes_original_stored_bytes_to_crypto(make_release, monkeypatch):
    case = make_release()
    received = []
    original = signature.verify
    def recording_verify(profile, pub, message, signed):
        received.append(message)
        return original(profile, pub, message, signed)
    monkeypatch.setattr(signature, "verify", recording_verify)
    assert case.verify()["valid"] is True
    assert received == [case.message]

@pytest.mark.parametrize("mutation,status", [
    pytest.param("U02", "ARTIFACT_MISMATCH", id="U02_same_size_byte_change"),
    pytest.param("U03-add", "ARTIFACT_MISMATCH", id="U03_add_byte"),
    pytest.param("U03-remove", "ARTIFACT_MISMATCH", id="U03_remove_byte"),
    pytest.param("U04", "INVALID_SIGNATURE", id="U04_changed_manifest_version_old_signature"),
    pytest.param("U08", "METADATA_MISMATCH", id="U08_wrong_expected_version"),
    pytest.param("U09", "METADATA_MISMATCH", id="U09_renamed_artifact"),
    pytest.param("U11", "UNSUPPORTED_ALGORITHM", id="U11_unknown_algorithm"),
    pytest.param("U13", "OK", id="U13_bundle_whitespace_and_order"),
])
def test_required_scenarios(make_release, mutation, status, capsys):
    case = make_release()
    argv = verify_args(case)
    if mutation == "U02":
        case.file.write_bytes(bytes([case.content[0] ^ 1]) + case.content[1:])
    elif mutation == "U03-add":
        case.file.write_bytes(case.content + b"x")
    elif mutation == "U03-remove":
        case.file.write_bytes(case.content[:-1])
    elif mutation == "U04":
        case.manifest["version"] = "2.0"
        case.write_message(manifest.serialize(case.manifest))
    elif mutation == "U08":
        argv[argv.index("--version") + 1] = "2.0"
    elif mutation == "U09":
        renamed = case.file.with_name("renamed.bin")
        case.file.rename(renamed)
        argv[argv.index("--file") + 1] = str(renamed)
    elif mutation == "U11":
        case.manifest["algorithm"] = "unknown-profile"
        case.write_message(manifest.serialize(case.manifest))
    elif mutation == "U13":
        obj = json.loads(case.output.read_bytes())
        case.output.write_text(json.dumps(dict(reversed(list(obj.items()))), indent=4))
    code = cli.main(argv)
    out = capsys.readouterr().out
    result = json.loads(out)
    assert code == (0 if status == "OK" else 1)
    assert result["status"] == status
    assert result["valid"] is (status == "OK")
    assert list(result) == list(cli.VERIFY_FIELDS)
    assert out.count("\n") == 1

@pytest.mark.parametrize("condition", [
    pytest.param("duplicate", id="U10_duplicate_field"),
    pytest.param("type", id="U10_wrong_type_boolean_size"),
    pytest.param("base64", id="U10_invalid_base64"),
    pytest.param("oversize", id="U10_manifest_over_16KiB"),
])
def test_U10_conditions_are_independent(make_release, condition, capsys):
    case = make_release()
    if condition == "duplicate":
        case.write_message(case.message.replace(b'"version":"1.0"', b'"version":"1.0","version":"1.0"'))
    elif condition == "type":
        case.write_message(case.message.replace(
            ('"size":' + str(len(case.content))).encode(), b'"size":true'))
    elif condition == "base64":
        obj = json.loads(case.output.read_bytes())
        obj["signature_b64"] = "invalid!"
        case.output.write_text(json.dumps(obj))
    else:
        case.write_message(b" " * (MAX_MANIFEST_BYTES + 1))
    assert cli.main(verify_args(case)) == 1
    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["status"] == "FORMAT_ERROR" and result["valid"] is False
    assert list(result) == list(cli.VERIFY_FIELDS)
    assert output.count("\n") == 1

@pytest.mark.parametrize("earlier", ["input", "format", "algorithm", "trust", "signature", "metadata"])
def test_first_failure_wins(make_release, earlier):
    case = make_release()
    case.file.write_bytes(b"wrong artifact")
    case.manifest["version"] = "wrong"
    if earlier in ("input", "format", "algorithm"):
        case.manifest["algorithm"] = "unknown"
    case.write_message(manifest.serialize(case.manifest))
    if earlier in ("input", "format"):
        case.trust.write_bytes(b"not JSON")
    if earlier == "input":
        case.file.unlink()
    if earlier == "trust":
        case.trust_object["keys"] = []
        case.save_trust()
    if earlier == "metadata":
        case.write_message(manifest.serialize(case.manifest), resign=True)
    expected = {"input": "INPUT_ERROR", "format": "FORMAT_ERROR",
                "algorithm": "UNSUPPORTED_ALGORITHM", "trust": "KEY_NOT_TRUSTED",
                "signature": "INVALID_SIGNATURE", "metadata": "METADATA_MISMATCH"}
    assert case.verify()["status"] == expected[earlier]

def test_format_validation_includes_unrelated_trust_entries(make_release):
    case = make_release()
    case.trust_object["keys"].append({"invalid": "unrelated entry"})
    case.save_trust()
    assert case.verify()["status"] == "FORMAT_ERROR"

def test_authorization_uses_expected_package_before_manifest_metadata(make_release):
    case = make_release()
    assert case.verify(package="other-app")["status"] == "KEY_NOT_TRUSTED"
    case.trust_object["keys"][0]["packages"].append("other-app")
    case.save_trust()
    assert case.verify(package="other-app")["status"] == "METADATA_MISMATCH"

def test_profile_mismatch_is_trust_failure_before_crypto(make_release, monkeypatch):
    case = make_release()
    case.manifest["algorithm"] = "rsa-pss-sha256"
    case.write_message(manifest.serialize(case.manifest))
    def must_not_verify(*args):
        pytest.fail("crypto called despite mismatching trusted profile")
    monkeypatch.setattr(signature, "verify", must_not_verify)
    assert case.verify()["status"] == "KEY_NOT_TRUSTED"

@pytest.mark.parametrize("length", [0, 1, 63, 65])
def test_valid_base64_wrong_signature_length_is_invalid_signature(make_release, length):
    case = make_release()
    case.output.write_bytes(bundle.serialize(case.message, b"x" * length))
    assert case.verify()["status"] == "INVALID_SIGNATURE"

def test_diagnostics_are_retained_after_reading_manifest(make_release):
    case = make_release()
    case.file.write_bytes(b"changed")
    result = case.verify()
    assert [result[k] for k in ("algorithm", "keyid", "package", "version")] == [
        case.profile, case.keyid, case.package, case.version]
    case.output.write_bytes(b"invalid JSON")
    result = case.verify()
    assert all(result[k] is None for k in ("algorithm", "keyid", "package", "version"))

def test_capture_uses_verified_content_and_default_does_not_retain(make_release):
    case = make_release()
    args = (case.file, case.output, case.trust, case.package, case.version)
    _, details = verify_details(*args)
    assert details.content is None
    result, details = verify_details(*args, capture=True)
    assert result["valid"] and details.content == case.content and details.sha256 == case.digest

def test_sign_refuses_overwrite_and_force_preserves_inputs(make_release):
    case = make_release()
    original = case.output.read_bytes()
    key_before = case.key.read_bytes()
    with pytest.raises(InputError):
        sign_release(case.file, case.package, case.version, case.key, case.output)
    assert case.output.read_bytes() == original
    case.file.write_bytes(b"new release")
    sign_release(case.file, case.package, case.version, case.key, case.output, force=True)
    assert case.verify()["valid"]
    assert case.key.read_bytes() == key_before
    assert case.file.read_bytes() == b"new release"

@pytest.mark.parametrize("destination", ["file", "key"])
def test_sign_refuses_input_alias_even_with_force(make_release, destination):
    case = make_release()
    target = getattr(case, destination)
    before = target.read_bytes()
    with pytest.raises(InputError):
        sign_release(case.file, case.package, case.version, case.key, target, force=True)
    assert target.read_bytes() == before

@pytest.mark.parametrize("fault", ["missing-file", "bad-key", "bad-package", "missing-parent"])
def test_sign_failures_exit_2_without_creating_output(make_release, fault, capsys):
    case = make_release()
    output = case.output.with_name("new.json")
    package = case.package
    if fault == "missing-file":
        case.file.unlink()
    elif fault == "bad-key":
        case.key.write_bytes(b"invalid private key")
    elif fault == "bad-package":
        package = "invalid package"
    else:
        output = output.parent / "missing-parent" / "bundle.json"
    code = cli.main(["sign", "--file", str(case.file), "--package", package, "--version", case.version,
                     "--key", str(case.key), "--out", str(output)])
    assert code == 2 and not output.exists()
    assert capsys.readouterr().out == ""

@pytest.mark.parametrize("missing", ["file", "output", "trust"])
def test_missing_input_returns_input_error_and_exit_2(make_release, missing, capsys):
    case = make_release()
    getattr(case, missing).unlink()
    assert cli.main(verify_args(case)) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "INPUT_ERROR"

def test_real_process_exit_code_and_stdout(make_release):
    case = make_release()
    for expected in (0, 1, 2):
        if expected == 1:
            case.file.write_bytes(b"changed")
        elif expected == 2:
            case.file.unlink()
        run = subprocess.run([sys.executable, "-m", "tacstmu", *verify_args(case)],
                             capture_output=True, text=True)
        assert run.returncode == expected
        assert json.loads(run.stdout)["status"] == ["OK", "ARTIFACT_MISMATCH", "INPUT_ERROR"][expected]
        assert run.stdout.count("\n") == 1

def test_atomic_write_failure_preserves_old_bundle_and_cleans_temp(tmp_path, monkeypatch):
    output = tmp_path / "bundle.json"
    output.write_bytes(b"old")
    def failure(*args):
        raise PermissionError("simulated publication failure")
    monkeypatch.setattr(files.os, "replace", failure)
    with pytest.raises(InputError):
        files.write_bundle(output, b"new", force=True)
    assert output.read_bytes() == b"old"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["bundle.json"]

def test_concurrent_create_is_not_overwritten(tmp_path, monkeypatch):
    output = tmp_path / "bundle.json"
    method = "rename" if os.name == "nt" else "link"
    publish = getattr(files.os, method)
    def racing_publish(source, target):
        output.write_bytes(b"another writer")
        return publish(source, target)
    monkeypatch.setattr(files.os, method, racing_publish)
    with pytest.raises(InputError):
        files.write_bundle(output, b"our bytes", force=False)
    assert output.read_bytes() == b"another writer"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["bundle.json"]

def test_streamed_snapshot_captures_multiple_chunks(tmp_path):
    import hashlib
    data = bytes(range(256)) * 8193
    path = tmp_path / "large.bin"
    path.write_bytes(data)
    assert files.snapshot(path, capture=True) == (len(data), hashlib.sha256(data).hexdigest(), data)

def test_correctly_signed_noncanonical_manifest_is_still_format_error(make_release):
    case = make_release()
    noncanonical = json.dumps(case.manifest, indent=2).encode()
    case.write_message(noncanonical, resign=True)
    assert case.verify()["status"] == "FORMAT_ERROR"

def test_artifact_read_permission_failure_is_input_error(make_release, monkeypatch):
    from tacstmu.release import verification
    case = make_release()
    def denied(*args, **kwargs):
        raise InputError("cannot read artifact: permission denied")
    monkeypatch.setattr(verification, "snapshot", denied)
    assert case.verify()["status"] == "INPUT_ERROR"

def test_different_existing_path_to_protected_input_is_refused(make_release, monkeypatch):
    case = make_release()
    alias = case.file.with_name("alias.bin")
    alias.write_bytes(b"existing alias")
    monkeypatch.setattr(files.os.path, "samefile", lambda left, right: True)
    with pytest.raises(InputError):
        files.write_bundle(alias, b"replacement", force=True, protected=(case.file,))
    assert alias.read_bytes() == b"existing alias"


@pytest.mark.parametrize("location", ["manifest", "bundle", "trust"], ids=[
    "U10_regression_huge_manifest_integer", "U10_regression_huge_bundle_integer",
    "U10_regression_huge_trust_integer",
])
def test_U10_large_integer_cli_format_error(make_release, location):
    case = make_release()
    digits = b"9" * 5000
    if location == "manifest":
        message = case.message.replace(
            ('"size":' + str(len(case.content))).encode(), b'"size":' + digits)
        assert len(message) < MAX_MANIFEST_BYTES
        case.write_message(message)
    elif location == "bundle":
        raw = case.output.read_bytes()
        case.output.write_bytes(raw.replace(b'"schema":"minisign-bundle/v1"', b'"schema":' + digits))
    else:
        raw = case.trust.read_bytes()
        case.trust.write_bytes(raw.replace(b'"schema": "minisign-trust/v1"', b'"schema":' + digits))
    # Test the real process exit, independently of in-process CLI error handling.
    run = subprocess.run([sys.executable, "-X", "int_max_str_digits=4300", "-m", "tacstmu",
                          *verify_args(case)], capture_output=True, text=True)
    assert run.returncode == 1
    result = json.loads(run.stdout)
    assert result["status"] == "FORMAT_ERROR" and result["valid"] is False
    assert list(result) == list(cli.VERIFY_FIELDS)
    assert "internal error" not in result["message"]
    assert run.stdout.count("\n") == 1

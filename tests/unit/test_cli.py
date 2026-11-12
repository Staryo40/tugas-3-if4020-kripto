import json
import subprocess
import sys

import pytest

from tacstmu import __version__, cli
from tacstmu.core.outcomes import FormatError, TacstmuError
from tacstmu.crypto import keys

VERIFY_ARGS = [
    "verify", "--file", "a.zip", "--bundle", "b.json", "--trust-store", "t.json",
    "--package", "contoh-app", "--version", "1.0.0",
]


def _result(status, valid=False, message="m"):
    return {
        "valid": valid, "status": status, "message": message,
        "algorithm": "ed25519", "keyid": "a" * 64, "package": "contoh-app", "version": "1.0.0",
    }


# Help and version
def test_version(capsys):
    assert cli.main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == f"tacstmu {__version__}"

@pytest.mark.parametrize("argv", [["--help"], ["keygen", "--help"], ["verify", "--help"], ["trust", "add", "--help"]])
def test_help(capsys, argv):
    assert cli.main(argv) == 0
    assert "usage:" in capsys.readouterr().out

def test_module_entry_point():
    run = subprocess.run([sys.executable, "-m", "tacstmu", "--version"], capture_output=True, text=True)
    assert run.returncode == 0
    assert run.stdout.strip() == f"tacstmu {__version__}"


# Usage errors
@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["unknown"],
        ["keygen", "--out", "x"],
        ["keygen", "--algorithm", "dsa", "--out", "x"],
        ["sign", "--file", "a.zip"],
        ["trust"],
        ["trust", "remove", "--store", "t.json"],
    ],
)
def test_usage_errors_exit_2(capsys, argv):
    assert cli.main(argv) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error:" in captured.err

def test_verify_json_usage_error_prints_input_error(capsys):
    assert cli.main(["verify", "--json", "--file", "a.zip"]) == 2
    out = capsys.readouterr().out
    assert out.endswith("\n") and out.count("\n") == 1
    result = json.loads(out)
    assert result["valid"] is False and result["status"] == "INPUT_ERROR"
    assert all(result[f] is None for f in ("algorithm", "keyid", "package", "version"))


# keygen
@pytest.mark.parametrize("profile", ["rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"])
def test_keygen(tmp_path, capsys, profile):
    prefix = tmp_path / "keys" / "publisher"
    assert cli.main(["keygen", "--algorithm", profile, "--out", str(prefix)]) == 0
    out = capsys.readouterr().out.strip()
    pub, loaded_profile = keys.load_public_pem((tmp_path / "keys" / "publisher.pub.pem").read_bytes())
    assert loaded_profile == profile
    assert out == keys.keyid(pub)

def test_keygen_refuses_overwrite(tmp_path, capsys):
    prefix = str(tmp_path / "publisher")
    assert cli.main(["keygen", "--algorithm", "ed25519", "--out", prefix]) == 0
    before = (tmp_path / "publisher.key.pem").read_bytes()
    assert cli.main(["keygen", "--algorithm", "ed25519", "--out", prefix]) == 2
    assert "overwrite" in capsys.readouterr().err
    assert (tmp_path / "publisher.key.pem").read_bytes() == before

def test_keygen_force(tmp_path):
    prefix = str(tmp_path / "publisher")
    cli.main(["keygen", "--algorithm", "ed25519", "--out", prefix])
    before = (tmp_path / "publisher.key.pem").read_bytes()
    assert cli.main(["keygen", "--algorithm", "ed25519", "--out", prefix, "--force"]) == 0
    assert (tmp_path / "publisher.key.pem").read_bytes() != before


# Verify reporting
@pytest.mark.parametrize(
    "status, valid, code",
    [
        ("OK", True, 0),
        ("FORMAT_ERROR", False, 1),
        ("KEY_NOT_TRUSTED", False, 1),
        ("ARTIFACT_MISMATCH", False, 1),
        ("INPUT_ERROR", False, 2),
        ("OK", False, 1),
    ],
)
def test_report_verify_exit_codes(capsys, status, valid, code):
    assert cli.report_verify(_result(status, valid), as_json=True) == code

def test_report_verify_json_format(capsys):
    cli.report_verify(_result("OK", True, "Tanda tangan dan artefak valid."), as_json=True)
    out = capsys.readouterr().out
    assert out.endswith("}\n") and out.count("\n") == 1
    assert list(json.loads(out)) == list(cli.VERIFY_FIELDS)

def test_report_verify_human_format(capsys):
    cli.report_verify(_result("KEY_NOT_TRUSTED", message="key not trusted"), as_json=False)
    assert capsys.readouterr().out == "KEY_NOT_TRUSTED: key not trusted\n"


# Error mapping
def test_non_verify_error_exits_2(monkeypatch, capsys):
    def boom(args):
        raise FormatError("bad trust store")
    monkeypatch.setattr(cli, "cmd_trust_list", boom)
    assert cli.main(["trust", "list", "--store", "t.json"]) == 2
    assert "bad trust store" in capsys.readouterr().err

@pytest.mark.parametrize(
    "error, status, code",
    [
        (FormatError("broken bundle"), "FORMAT_ERROR", 1),
        (TacstmuError("unclassified"), "INPUT_ERROR", 2),
        (RuntimeError("bug"), "INPUT_ERROR", 2),
    ],
)
def test_verify_error_mapping(monkeypatch, capsys, error, status, code):
    def boom(args):
        raise error
    monkeypatch.setattr(cli, "cmd_verify", boom)
    assert cli.main([*VERIFY_ARGS, "--json"]) == code
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == status and result["valid"] is False

def test_placeholder_commands_exit_0(capsys):
    assert cli.main(VERIFY_ARGS) == 0

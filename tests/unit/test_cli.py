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


# Help, version and entry point
def test_version(capsys):
    assert cli.main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == f"tacstmu {__version__}"

def test_help(capsys):
    assert cli.main(["--help"]) == 0
    assert "usage:" in capsys.readouterr().out

def test_module_entry_point():
    run = subprocess.run([sys.executable, "-m", "tacstmu", "--version"], capture_output=True, text=True)
    assert run.returncode == 0
    assert run.stdout.strip() == f"tacstmu {__version__}"


# Usage errors
@pytest.mark.parametrize(
    "argv",
    [
        pytest.param([], id="no-command"),
        pytest.param(["keygen", "--out", "x"], id="missing-flag"),
        pytest.param(["keygen", "--algorithm", "dsa", "--out", "x"], id="bad-choice"),
    ],
)
def test_usage_errors_exit_2(capsys, argv):
    assert cli.main(argv) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "error:" in captured.err

def test_verify_json_usage_error_prints_input_error(capsys):
    assert cli.main(["verify", "--json", "--file", "a.zip"]) == 2
    out = capsys.readouterr().out
    assert out.count("\n") == 1
    result = json.loads(out)
    assert result["status"] == "INPUT_ERROR" and result["keyid"] is None


# keygen
def test_keygen(tmp_path, capsys):
    prefix = tmp_path / "keys" / "publisher"
    assert cli.main(["keygen", "--algorithm", "ed25519", "--out", str(prefix)]) == 0
    pub, profile = keys.load_public_pem((tmp_path / "keys" / "publisher.pub.pem").read_bytes())
    assert profile == "ed25519"
    assert capsys.readouterr().out.strip() == keys.keyid(pub)

def test_keygen_refuses_overwrite(tmp_path, capsys):
    prefix = str(tmp_path / "publisher")
    cli.main(["keygen", "--algorithm", "ed25519", "--out", prefix])
    assert cli.main(["keygen", "--algorithm", "ed25519", "--out", prefix]) == 2
    assert "overwrite" in capsys.readouterr().err

def test_keygen_force(tmp_path):
    prefix = str(tmp_path / "publisher")
    cli.main(["keygen", "--algorithm", "ed25519", "--out", prefix])
    before = (tmp_path / "publisher.key.pem").read_bytes()
    assert cli.main(["keygen", "--algorithm", "ed25519", "--out", prefix, "--force"]) == 0
    assert (tmp_path / "publisher.key.pem").read_bytes() != before


# Verify reporting
@pytest.mark.parametrize("status, valid, code", [("OK", True, 0), ("FORMAT_ERROR", False, 1), ("INPUT_ERROR", False, 2)])
def test_report_verify_exit_codes(capsys, status, valid, code):
    assert cli.report_verify(_result(status, valid), as_json=True) == code

def test_report_verify_json_format(capsys):
    cli.report_verify(_result("OK", True), as_json=True)
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
    "error",
    [pytest.param(TacstmuError("unclassified"), id="base-error"), pytest.param(RuntimeError("bug"), id="crash")],
)
def test_verify_unclassified_error_is_input_error(monkeypatch, capsys, error):
    def boom(args):
        raise error
    monkeypatch.setattr(cli, "cmd_verify", boom)
    assert cli.main([*VERIFY_ARGS, "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "INPUT_ERROR"

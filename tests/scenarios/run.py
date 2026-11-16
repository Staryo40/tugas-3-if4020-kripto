import base64
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
KEYS = REPO / "tests" / "keys"
RESULTS = REPO / "tests" / "results" / "scenarios"

PROFILES = ("rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519")
DEFAULT_PROFILE = "ed25519"
OTHER_KEY = "ed25519-other"
PACKAGE = "contoh-app"
VERSION = "1.0.0"

ARTIFACTS = {
    "text": ("contoh-app.txt", b"contoh-app 1.0.0 release notes\nAll bugs fixed. Probably.\n"),
    "binary": ("contoh-app.bin", bytes(range(256)) * 16),
    "empty": ("contoh-app-empty.bin", b""),
}


# Scenario folder: run commands and record evidence
class Scenario:
    def __init__(self, scenario_id: str, profile: str, kind: str = "text"):
        self.id = scenario_id
        self.profile = profile
        self.folder = RESULTS / scenario_id
        self.input = self.folder / "input"
        self.input.mkdir(parents=True)
        self.log = []
        self.artifact_name, data = ARTIFACTS[kind]
        self.artifact = self.input / self.artifact_name
        self.artifact.write_bytes(data)
        self.bundle = self.input / "bundle.json"
        self.trust = self.input / "trust.json"

    def run(self, label: str, *args: str) -> subprocess.CompletedProcess:
        result = subprocess.run(
            [sys.executable, "-m", "tacstmu", *args],
            cwd=self.folder, capture_output=True, stdin=subprocess.DEVNULL, timeout=120,
        )
        self.log.append(log_entry(label, ["tacstmu", *args], result))
        return result

    def rel(self, path: Path) -> str:
        return os.path.relpath(path, self.folder)

    def trust_key(self, key: str, package: str = PACKAGE, label: str = "trust-add") -> None:
        self._check(self.run(label, "trust", "add", "--key", self.rel(KEYS / f"{key}.pub.pem"),
                             "--package", package, "--store", self.rel(self.trust)))

    def sign(self, key: str | None = None, out: Path | None = None, label: str = "sign") -> None:
        key = key or self.profile
        self._check(self.run(label, "sign", "--file", self.rel(self.artifact), "--package", PACKAGE,
                             "--version", VERSION, "--key", self.rel(KEYS / f"{key}.key.pem"),
                             "--out", self.rel(out or self.bundle)))

    def setup(self) -> "Scenario":
        self.trust_key(self.profile)
        self.sign()
        return self

    def verify(self, *, file: Path | None = None, bundle: Path | None = None,
               package: str = PACKAGE, version: str = VERSION, label: str = "verify") -> dict:
        result = self.run(label, "verify", "--file", self.rel(file or self.artifact),
                          "--bundle", self.rel(bundle or self.bundle), "--trust-store", self.rel(self.trust),
                          "--package", package, "--version", version, "--json")
        output = json.loads(result.stdout)
        return {"exit_code": result.returncode, "status": output["status"], "valid": output["valid"]}

    def finish(self, description: str, expected: dict, actual: dict, extra: dict | None = None) -> dict:
        passed = all(actual.get(name) == value for name, value in expected.items())
        _write_json(self.folder / "log.json", self.log)
        _write_json(self.folder / "expected.json", {"description": description, **expected})
        _write_json(self.folder / "actual.json", {**actual, **(extra or {}), "passed": passed})
        print(f"{'PASS' if passed else 'FAIL'}  {self.id}")
        return {"id": self.id, "profile": self.profile, "description": description,
                "expected": expected, "actual": actual, "passed": passed}

    @staticmethod
    def _check(result: subprocess.CompletedProcess) -> None:
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode(errors="replace").strip())


# Bundle and manifest editing
def read_bundle(path: Path) -> tuple[bytes, bytes]:
    obj = json.loads(path.read_bytes())
    return base64.b64decode(obj["manifest_b64"]), base64.b64decode(obj["signature_b64"])

def write_bundle(path: Path, manifest: bytes, signature: bytes) -> None:
    path.write_text(json.dumps({
        "schema": "minisign-bundle/v1",
        "manifest_b64": base64.b64encode(manifest).decode(),
        "signature_b64": base64.b64encode(signature).decode(),
    }, separators=(",", ":")))

def edit_manifest(scenario: Scenario, old: bytes, new: bytes) -> None:
    manifest, signature = read_bundle(scenario.bundle)
    assert old in manifest, f"{old!r} not in manifest"
    write_bundle(scenario.bundle, manifest.replace(old, new, 1), signature)

def _write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


# Process log entries
def log_entry(step: str, command: list[str], result: subprocess.CompletedProcess) -> dict:
    return {"step": step, "command": shlex.join(command), "exit_code": result.returncode,
            "stdout": _readable(result.stdout), "stderr": _readable(result.stderr)}

def _readable(output: bytes) -> object:
    # JSON output stays structured, multi-line text becomes a list of lines
    text = output.decode(errors="replace").rstrip("\n")
    if not text:
        return ""
    try:
        return json.loads(text)
    except ValueError:
        return text.splitlines() if "\n" in text else text

def _expect(status: str) -> dict:
    code = 0 if status == "OK" else 2 if status == "INPUT_ERROR" else 1
    return {"exit_code": code, "status": status, "valid": status == "OK"}


# Scenarios
def u01() -> list[dict]:
    rows = []
    for profile in PROFILES:
        for kind in ARTIFACTS:
            s = Scenario(f"U01-{kind}-{profile}", profile, kind).setup()
            rows.append(s.finish(f"Sign and verify a {kind} file", _expect("OK"), s.verify()))
    return rows

def u02() -> list[dict]:
    s = Scenario("U02-byte-changed", DEFAULT_PROFILE).setup()
    data = bytearray(s.artifact.read_bytes())
    data[0] ^= 0x01
    s.artifact.write_bytes(bytes(data))
    return [s.finish("One artifact byte changed, same size and name", _expect("ARTIFACT_MISMATCH"), s.verify())]

def u03() -> list[dict]:
    rows = []
    for variant, change in (("added", lambda d: d + b"!"), ("removed", lambda d: d[:-1])):
        s = Scenario(f"U03-byte-{variant}", DEFAULT_PROFILE).setup()
        s.artifact.write_bytes(change(s.artifact.read_bytes()))
        rows.append(s.finish(f"One artifact byte {variant}", _expect("ARTIFACT_MISMATCH"), s.verify()))
    return rows

def u04() -> list[dict]:
    s = Scenario("U04-manifest-version-changed", DEFAULT_PROFILE).setup()
    edit_manifest(s, b'"version":"1.0.0"', b'"version":"1.0.1"')
    return [s.finish("Manifest version changed (still canonical), old signature kept",
                     _expect("INVALID_SIGNATURE"), s.verify(version="1.0.1"))]

def u05() -> list[dict]:
    s = Scenario("U05-signature-bit-flipped", DEFAULT_PROFILE).setup()
    manifest, signature = read_bundle(s.bundle)
    flipped = bytearray(signature)
    flipped[10] ^= 0x01
    write_bundle(s.bundle, manifest, bytes(flipped))
    return [s.finish("One signature bit flipped, same length, valid Base64",
                     _expect("INVALID_SIGNATURE"), s.verify())]

def u06() -> list[dict]:
    empty = Scenario("U06-empty-trust-store", DEFAULT_PROFILE).setup()
    empty.trust.write_text('{"schema":"minisign-trust/v1","keys":[]}\n')
    rows = [empty.finish("Empty trust store", _expect("KEY_NOT_TRUSTED"), empty.verify())]

    removed = Scenario("U06-publisher-key-removed", DEFAULT_PROFILE).setup()
    keyid = json.loads(removed.trust.read_bytes())["keys"][0]["keyid"]
    removed._check(removed.run("trust-remove", "trust", "remove", "--keyid", keyid,
                               "--store", removed.rel(removed.trust)))
    rows.append(removed.finish("Publisher key removed from the trust store",
                               _expect("KEY_NOT_TRUSTED"), removed.verify()))
    return rows

def u07() -> list[dict]:
    s = Scenario("U07-key-for-other-package", DEFAULT_PROFILE)
    s.trust_key(s.profile, package="other-app")
    s.sign()
    return [s.finish("Key trusted only for another package", _expect("KEY_NOT_TRUSTED"), s.verify())]

def u08() -> list[dict]:
    s = Scenario("U08-expected-version-differs", DEFAULT_PROFILE).setup()
    return [s.finish("Valid bundle, verified with a different expected version",
                     _expect("METADATA_MISMATCH"), s.verify(version="2.0.0"))]

def u09() -> list[dict]:
    s = Scenario("U09-artifact-renamed", DEFAULT_PROFILE).setup()
    renamed = s.artifact.with_name("contoh-app-renamed.txt")
    s.artifact.rename(renamed)
    return [s.finish("Artifact file renamed, content unchanged",
                     _expect("METADATA_MISMATCH"), s.verify(file=renamed))]

def u10() -> list[dict]:
    rows = []

    s = Scenario("U10-duplicate-field", DEFAULT_PROFILE).setup()
    text = s.bundle.read_text()
    s.bundle.write_text(text.replace('{"schema":', '{"schema":"minisign-bundle/v1","schema":', 1))
    rows.append(s.finish("Bundle with a duplicate field", _expect("FORMAT_ERROR"), s.verify()))

    s = Scenario("U10-wrong-type", DEFAULT_PROFILE).setup()
    manifest, signature = read_bundle(s.bundle)
    write_bundle(s.bundle, re.sub(rb'"size":\d+', b'"size":true', manifest), signature)
    rows.append(s.finish("Manifest artifact size is a boolean", _expect("FORMAT_ERROR"), s.verify()))

    s = Scenario("U10-invalid-base64", DEFAULT_PROFILE).setup()
    obj = json.loads(s.bundle.read_bytes())
    obj["signature_b64"] = obj["signature_b64"][:-4] + "!!!!"
    s.bundle.write_text(json.dumps(obj, separators=(",", ":")))
    rows.append(s.finish("Signature is not valid Base64", _expect("FORMAT_ERROR"), s.verify()))

    s = Scenario("U10-manifest-too-large", DEFAULT_PROFILE).setup()
    manifest, signature = read_bundle(s.bundle)
    write_bundle(s.bundle, manifest + b" " * (16 * 1024), signature)
    rows.append(s.finish("Manifest larger than 16 KiB", _expect("FORMAT_ERROR"), s.verify()))
    return rows

def u11() -> list[dict]:
    s = Scenario("U11-unsupported-algorithm", DEFAULT_PROFILE).setup()
    edit_manifest(s, b'"algorithm":"ed25519"', b'"algorithm":"ed448"')
    return [s.finish("Manifest algorithm is an unsupported profile",
                     _expect("UNSUPPORTED_ALGORITHM"), s.verify())]

def u12() -> list[dict]:
    s = Scenario("U12-untrusted-same-profile-key", DEFAULT_PROFILE)
    s.trust_key(s.profile)
    s.sign(key=OTHER_KEY)
    return [s.finish("Signed by another key of the same profile, not in the trust store",
                     _expect("KEY_NOT_TRUSTED"), s.verify())]

def u13() -> list[dict]:
    s = Scenario("U13-bundle-reformatted", DEFAULT_PROFILE).setup()
    obj = json.loads(s.bundle.read_bytes())
    s.bundle.write_text(json.dumps(dict(reversed(list(obj.items()))), indent=4) + "\n")
    return [s.finish("Bundle whitespace and field order changed, Base64 strings kept",
                     _expect("OK"), s.verify())]

def u14() -> list[dict]:
    rows = []
    for profile in PROFILES:
        s = Scenario(f"U14-sign-twice-{profile}", profile)
        s.trust_key(profile)
        first, second = s.input / "bundle-1.json", s.input / "bundle-2.json"
        s.sign(out=first, label="sign-1")
        s.sign(out=second, label="sign-2")
        a, b = s.verify(bundle=first, label="verify-1"), s.verify(bundle=second, label="verify-2")
        identical = read_bundle(first)[1] == read_bundle(second)[1]
        expected = {"both_valid": True, "signatures_identical": profile == "ed25519"}
        actual = {"both_valid": a["status"] == b["status"] == "OK", "signatures_identical": identical}
        rows.append(s.finish("Identical manifest signed twice with the same key",
                             expected, actual, extra={"verify_1": a, "verify_2": b}))
    return rows

SCENARIOS = (u01, u02, u03, u04, u05, u06, u07, u08, u09, u10, u11, u12, u13, u14)


def main() -> int:
    needed = [KEYS / f"{name}.{part}.pem" for name in (*PROFILES, OTHER_KEY) for part in ("key", "pub")]
    missing = [str(p.relative_to(REPO)) for p in needed if not p.exists()]
    if missing:
        print("missing test keys: " + ", ".join(missing), file=sys.stderr)
        return 2

    shutil.rmtree(RESULTS, ignore_errors=True)
    RESULTS.mkdir(parents=True)

    rows = [row for scenario in SCENARIOS for row in scenario()]
    passed = sum(row["passed"] for row in rows)
    _write_json(RESULTS / "summary.json", {"passed": passed, "total": len(rows), "scenarios": rows})
    print(f"\n{passed}/{len(rows)} scenarios passed, results in {RESULTS.relative_to(REPO)}")
    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())

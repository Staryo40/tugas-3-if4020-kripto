import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[2]
KEYS = REPO / "tests" / "keys"
RESULTS = REPO / "tests" / "results" / "interop"

PROFILES = ("rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519")
PACKAGE = "contoh-app"
VERSION = "1.0.0"
ARTIFACT = ("contoh-app.txt", b"contoh-app 1.0.0 interop artifact\n")

RSA_PSS_OPTS = ["-pkeyopt", "rsa_padding_mode:pss", "-pkeyopt", "rsa_pss_saltlen:32",
                "-pkeyopt", "rsa_mgf1_md:sha256"]
GENPKEY_OPTS = {
    "rsa-pss-sha256": ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072",
                       "-pkeyopt", "rsa_keygen_pubexp:65537"],
    "ecdsa-p256-sha256": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                          "-pkeyopt", "ec_param_enc:named_curve"],
    "ed25519": ["-algorithm", "ED25519"],
}


# Case folder: run commands and record evidence
class Case:
    def __init__(self, case_id: str, profile: str):
        self.id = case_id
        self.profile = profile
        self.folder = RESULTS / case_id
        self.input = self.folder / "input"
        self.input.mkdir(parents=True)
        self.commands = []
        self.artifact = self.input / ARTIFACT[0]
        self.artifact.write_bytes(ARTIFACT[1])
        self.bundle = self.input / "bundle.json"
        self.trust = self.input / "trust.json"
        self.manifest = self.input / "manifest.bin"
        self.signature = self.input / "signature.bin"

    def run(self, label: str, *argv: str) -> subprocess.CompletedProcess:
        self.commands.append({"label": label, "command": list(argv)})
        executable = [sys.executable, "-m", "tacstmu", *argv[1:]] if argv[0] == "tacstmu" else list(argv)
        result = subprocess.run(executable, cwd=self.folder, capture_output=True,
                                stdin=subprocess.DEVNULL, timeout=120)
        (self.folder / f"{label}.stdout.log").write_bytes(result.stdout)
        (self.folder / f"{label}.stderr.log").write_bytes(result.stderr)
        (self.folder / f"{label}.exit-code.txt").write_text(f"{result.returncode}\n")
        return result

    def must(self, label: str, *argv: str) -> subprocess.CompletedProcess:
        result = self.run(label, *argv)
        if result.returncode != 0:
            raise RuntimeError(f"{self.id}: {label} failed: {result.stderr.decode(errors='replace').strip()}")
        return result

    def rel(self, path: Path) -> str:
        return os.path.relpath(path, self.folder)

    def finish(self, description: str, expected: dict, actual: dict) -> dict:
        passed = all(actual.get(name) == value for name, value in expected.items())
        _write_json(self.folder / "commands.json", self.commands)
        _write_json(self.folder / "expected.json", {"description": description, **expected})
        _write_json(self.folder / "actual.json", {**actual, "passed": passed})
        print(f"{'PASS' if passed else 'FAIL'}  {self.id}")
        return {"id": self.id, "profile": self.profile, "description": description,
                "expected": expected, "actual": actual, "passed": passed}


# OpenSSL commands per profile
def openssl_verify(case: Case, label: str, pub: Path, message: Path, signature: Path) -> subprocess.CompletedProcess:
    if case.profile == "ecdsa-p256-sha256":
        return case.run(label, "openssl", "dgst", "-sha256", "-verify", case.rel(pub),
                        "-signature", case.rel(signature), case.rel(message))
    extra = ["-digest", "sha256", *RSA_PSS_OPTS] if case.profile == "rsa-pss-sha256" else []
    return case.run(label, "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", case.rel(pub), "-rawin",
                    *extra, "-in", case.rel(message), "-sigfile", case.rel(signature))

def openssl_sign(case: Case, label: str, key: Path, message: Path, out: Path) -> None:
    if case.profile == "ecdsa-p256-sha256":
        case.must(label, "openssl", "dgst", "-sha256", "-sign", str(key), "-out", case.rel(out), case.rel(message))
        return
    extra = ["-digest", "sha256", *RSA_PSS_OPTS] if case.profile == "rsa-pss-sha256" else []
    case.must(label, "openssl", "pkeyutl", "-sign", "-inkey", str(key), "-rawin", *extra,
              "-in", case.rel(message), "-out", case.rel(out))


# ECDSA signature encodings, written independently of the tool
def raw_to_der(raw: bytes) -> bytes:
    def integer(value: bytes) -> bytes:
        value = value.lstrip(b"\x00") or b"\x00"
        if value[0] & 0x80:
            value = b"\x00" + value
        return b"\x02" + bytes([len(value)]) + value
    body = integer(raw[:32]) + integer(raw[32:])
    return b"\x30" + bytes([len(body)]) + body

def der_to_raw(der: bytes) -> bytes:
    assert der[0] == 0x30 and der[1] == len(der) - 2, "unexpected DER sequence"
    values, offset = [], 2
    for _ in range(2):
        assert der[offset] == 0x02, "expected DER integer"
        length = der[offset + 1]
        values.append(int.from_bytes(der[offset + 2:offset + 2 + length], "big"))
        offset += 2 + length
    return b"".join(value.to_bytes(32, "big") for value in values)


# Bundle helpers
def split_bundle(case: Case) -> tuple[bytes, bytes]:
    obj = json.loads(case.bundle.read_bytes())
    manifest, signature = base64.b64decode(obj["manifest_b64"]), base64.b64decode(obj["signature_b64"])
    case.manifest.write_bytes(manifest)
    case.signature.write_bytes(signature)
    return manifest, signature

def replace_signature(case: Case, signature: bytes) -> None:
    obj = json.loads(case.bundle.read_bytes())
    obj["signature_b64"] = base64.b64encode(signature).decode()
    case.bundle.write_text(json.dumps(obj, separators=(",", ":")))

def _write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


# Cases
def ours_to_openssl(profile: str) -> dict:
    case = Case(f"{profile}-tacstmu-to-openssl", profile)
    pub = KEYS / f"{profile}.pub.pem"
    case.must("trust-add", "tacstmu", "trust", "add", "--key", case.rel(pub),
              "--package", PACKAGE, "--store", case.rel(case.trust))
    case.must("sign", "tacstmu", "sign", "--file", case.rel(case.artifact), "--package", PACKAGE,
              "--version", VERSION, "--key", case.rel(KEYS / f"{profile}.key.pem"), "--out", case.rel(case.bundle))
    _, signature = split_bundle(case)

    checked = case.signature
    if profile == "ecdsa-p256-sha256":
        checked = case.input / "signature.der"
        checked.write_bytes(raw_to_der(signature))
    verified = openssl_verify(case, "openssl-verify", pub, case.manifest, checked)

    tampered = case.input / "manifest-tampered.bin"
    tampered.write_bytes(case.manifest.read_bytes().replace(b"1.0.0", b"1.0.1", 1))
    rejected = openssl_verify(case, "openssl-verify-tampered", pub, tampered, checked)

    return case.finish(
        "OpenSSL verifies a tacstmu signature, and rejects it for a tampered manifest",
        {"openssl_accepts": True, "openssl_rejects_tampered": True},
        {"openssl_accepts": verified.returncode == 0, "openssl_rejects_tampered": rejected.returncode != 0},
    )

def openssl_to_ours(profile: str, scratch: Path) -> dict:
    case = Case(f"{profile}-openssl-to-tacstmu", profile)
    key = scratch / f"{profile}.key.pem"
    pub = case.input / "openssl.pub.pem"
    case.must("openssl-genpkey", "openssl", "genpkey", *GENPKEY_OPTS[profile], "-out", str(key))
    case.must("openssl-pubout", "openssl", "pkey", "-in", str(key), "-pubout", "-out", case.rel(pub))
    case.must("trust-add", "tacstmu", "trust", "add", "--key", case.rel(pub),
              "--package", PACKAGE, "--store", case.rel(case.trust))
    case.must("sign", "tacstmu", "sign", "--file", case.rel(case.artifact), "--package", PACKAGE,
              "--version", VERSION, "--key", str(key), "--out", case.rel(case.bundle))
    _, ours = split_bundle(case)

    produced = case.input / ("openssl-signature.der" if profile == "ecdsa-p256-sha256" else "openssl-signature.bin")
    openssl_sign(case, "openssl-sign", key, case.manifest, produced)
    theirs = der_to_raw(produced.read_bytes()) if profile == "ecdsa-p256-sha256" else produced.read_bytes()
    replace_signature(case, theirs)

    result = case.run("verify", "tacstmu", "verify", "--file", case.rel(case.artifact),
                      "--bundle", case.rel(case.bundle), "--trust-store", case.rel(case.trust),
                      "--package", PACKAGE, "--version", VERSION, "--json")
    output = json.loads(result.stdout)
    return case.finish(
        "tacstmu loads an OpenSSL key pair and verifies an OpenSSL signature",
        {"exit_code": 0, "status": "OK", "signature_identical_to_tacstmu": profile == "ed25519"},
        {"exit_code": result.returncode, "status": output["status"],
         "signature_identical_to_tacstmu": theirs == ours},
    )


def main() -> int:
    if shutil.which("openssl") is None:
        print("openssl not found on PATH", file=sys.stderr)
        return 2
    missing = [p for name in PROFILES for p in (KEYS / f"{name}.key.pem", KEYS / f"{name}.pub.pem") if not p.exists()]
    if missing:
        print("missing test keys: " + ", ".join(str(p.relative_to(REPO)) for p in missing), file=sys.stderr)
        return 2

    shutil.rmtree(RESULTS, ignore_errors=True)
    RESULTS.mkdir(parents=True)
    version = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout.strip()

    rows = []
    with tempfile.TemporaryDirectory(prefix="tacstmu-interop-") as scratch:
        for profile in PROFILES:
            rows.append(ours_to_openssl(profile))
            rows.append(openssl_to_ours(profile, Path(scratch)))

    passed = sum(row["passed"] for row in rows)
    _write_json(RESULTS / "summary.json",
                {"openssl": version, "passed": passed, "total": len(rows), "cases": rows})
    print(f"\n{passed}/{len(rows)} interop cases passed ({version}), results in {RESULTS.relative_to(REPO)}")
    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())

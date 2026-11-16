import csv
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

import cryptography
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import serialization

from tacstmu import __version__
from tacstmu.core.artifact import hash_file
from tacstmu.crypto import keys, signature
from tacstmu.release import manifest

REPO = Path(__file__).resolve().parents[2]
KEYS = REPO / "tests" / "keys"
RESULTS = REPO / "tests" / "results" / "benchmarks"

PROFILES = ("rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519")
SIZES = {"1KiB": 1024, "1MiB": 1024 * 1024, "100MiB": 100 * 1024 * 1024}
PACKAGE = "contoh-app"
VERSION = "1.0.0"

WARMUP = 5
RUNS_RAW = 100
RUNS_E2E = 30
RUNS_KEYGEN = 10


# Timing and statistics
def measure(samples: list, metric: str, profile: str, artifact: str, runs: int, warmup: int, action) -> None:
    for _ in range(warmup):
        action()
    for run in range(1, runs + 1):
        start = time.perf_counter_ns()
        action()
        samples.append({"metric": metric, "profile": profile, "artifact": artifact, "run": run,
                        "ns": time.perf_counter_ns() - start})
    print(f"  {metric:<12} {profile:<18} {artifact}", file=sys.stderr, flush=True)

def p95_nearest_rank(values: list[int]) -> int:
    ordered = sorted(values)
    return ordered[math.ceil(0.95 * len(ordered)) - 1]

def summarize(samples: list) -> list[dict]:
    groups: dict[tuple, list[int]] = {}
    for s in samples:
        groups.setdefault((s["metric"], s["profile"], s["artifact"]), []).append(s["ns"])
    return [{
        "metric": metric, "profile": profile, "artifact": artifact, "n": len(values),
        "median_ms": round(statistics.median(values) / 1e6, 4),
        "p95_ms": round(p95_nearest_rank(values) / 1e6, 4),
        "min_ms": round(min(values) / 1e6, 4), "max_ms": round(max(values) / 1e6, 4),
    } for (metric, profile, artifact), values in groups.items()]


# Benchmarked operations
def bench_keygen(samples: list) -> None:
    for profile in PROFILES:
        measure(samples, "keygen", profile, "-", RUNS_KEYGEN, 0, lambda: keys.generate(profile))

def bench_hash(samples: list, artifacts: dict[str, Path]) -> None:
    for label, path in artifacts.items():
        measure(samples, "hash", "-", label, RUNS_RAW, WARMUP, lambda: hash_file(path))

def bench_raw(samples: list, artifacts: dict[str, Path]) -> None:
    for profile in PROFILES:
        key = keys.generate(profile)
        pub = key.public_key()
        for label, path in artifacts.items():
            size, digest = hash_file(path)
            message = manifest.build(PACKAGE, VERSION, profile, keys.keyid(pub), path.name, size, digest)
            sig = signature.sign(profile, key, message)
            measure(samples, "sign_raw", profile, label, RUNS_RAW, WARMUP,
                    lambda: signature.sign(profile, key, message))
            measure(samples, "verify_raw", profile, label, RUNS_RAW, WARMUP,
                    lambda: signature.verify(profile, pub, message, sig))

def bench_e2e(samples: list, artifacts: dict[str, Path], work: Path) -> None:
    for profile in PROFILES:
        trust = work / f"trust-{profile}.json"
        _cli("trust", "add", "--key", str(KEYS / f"{profile}.pub.pem"), "--package", PACKAGE,
             "--store", str(trust))
        for label, path in artifacts.items():
            bundle = work / f"bundle-{profile}-{label}.json"
            sign = ("sign", "--file", str(path), "--package", PACKAGE, "--version", VERSION,
                    "--key", str(KEYS / f"{profile}.key.pem"), "--out", str(bundle), "--force")
            verify = ("verify", "--file", str(path), "--bundle", str(bundle), "--trust-store", str(trust),
                      "--package", PACKAGE, "--version", VERSION, "--json")
            measure(samples, "sign_e2e", profile, label, RUNS_E2E, WARMUP, lambda: _cli(*sign))
            measure(samples, "verify_e2e", profile, label, RUNS_E2E, WARMUP, lambda: _cli(*verify))

def collect_sizes(artifacts: dict[str, Path], work: Path) -> list[dict]:
    rows = []
    for profile in PROFILES:
        key, _ = keys.load_private_pem((KEYS / f"{profile}.key.pem").read_bytes())
        private_der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption())
        rows += [
            {"profile": profile, "item": "public_key_der", "bytes": len(keys.public_der(key.public_key()))},
            {"profile": profile, "item": "private_key_der", "bytes": len(private_der)},
            {"profile": profile, "item": "signature_raw",
             "bytes": len(signature.sign(profile, key, b"size probe"))},
        ]
        rows += [{"profile": profile, "item": f"bundle_{label}",
                  "bytes": (work / f"bundle-{profile}-{label}.json").stat().st_size} for label in artifacts]
    return rows

def _cli(*args: str) -> None:
    result = subprocess.run([sys.executable, "-m", "tacstmu", *args], capture_output=True,
                            stdin=subprocess.DEVNULL)
    if result.returncode != 0:
        raise RuntimeError(f"tacstmu {args[0]} failed: {result.stderr.decode(errors='replace').strip()}")


# Environment and output
def environment() -> dict:
    def first(path: str, key: str) -> str | None:
        try:
            for line in Path(path).read_text().splitlines():
                if line.startswith(key):
                    return line.split(":", 1)[1].strip()
        except OSError:
            return None
        return None
    clock = time.get_clock_info("perf_counter")
    return {
        "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cpu": first("/proc/cpuinfo", "model name") or platform.processor(),
        "logical_cores": os.cpu_count(),
        "memory_total": first("/proc/meminfo", "MemTotal"),
        "os": platform.platform(),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "cryptography": cryptography.__version__,
        "openssl_backend": backend.openssl_version_text(),
        "tacstmu": __version__,
        "timer": {"function": "time.perf_counter_ns", "monotonic": clock.monotonic,
                  "resolution_s": clock.resolution},
        "percentile_method": "nearest-rank: P95 = sorted[ceil(0.95 * n)] with positions starting at 1",
        "runs": {"warmup": WARMUP, "raw_and_hash": RUNS_RAW, "end_to_end": RUNS_E2E, "keygen": RUNS_KEYGEN},
        "artifact_sizes_bytes": SIZES,
        "artifacts": "random bytes, created in a temporary folder, identical for every algorithm",
    }

def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    missing = [p for name in PROFILES for p in (KEYS / f"{name}.key.pem", KEYS / f"{name}.pub.pem") if not p.exists()]
    if missing:
        print("missing test keys: " + ", ".join(str(p.relative_to(REPO)) for p in missing), file=sys.stderr)
        return 2

    shutil.rmtree(RESULTS, ignore_errors=True)
    RESULTS.mkdir(parents=True)
    samples: list = []

    with tempfile.TemporaryDirectory(prefix="tacstmu-bench-") as scratch:
        work = Path(scratch)
        artifacts = {}
        for label, size in SIZES.items():
            path = work / f"artifact-{label}.bin"
            with path.open("wb") as f:
                for offset in range(0, size, 1024 * 1024):
                    f.write(os.urandom(min(1024 * 1024, size - offset)))
            artifacts[label] = path

        print("keygen", file=sys.stderr)
        bench_keygen(samples)
        print("artifact hashing", file=sys.stderr)
        bench_hash(samples, artifacts)
        print("raw sign/verify", file=sys.stderr)
        bench_raw(samples, artifacts)
        print("end-to-end commands", file=sys.stderr)
        bench_e2e(samples, artifacts, work)
        sizes = collect_sizes(artifacts, work)

    summary = summarize(samples)
    write_csv(RESULTS / "raw.csv", samples)
    write_csv(RESULTS / "summary.csv", summary)
    write_csv(RESULTS / "sizes.csv", sizes)
    (RESULTS / "environment.json").write_text(json.dumps(environment(), indent=2) + "\n")

    print(f"\n{'metric':<12} {'profile':<18} {'artifact':<8} {'median ms':>10} {'p95 ms':>10}")
    for row in summary:
        print(f"{row['metric']:<12} {row['profile']:<18} {row['artifact']:<8} "
              f"{row['median_ms']:>10.4f} {row['p95_ms']:>10.4f}")
    print(f"\nresults in {RESULTS.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

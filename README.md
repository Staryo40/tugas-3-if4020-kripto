# Totally Awesome CI/CD Signing Tool Must Use 2026 (仮): Sign and verify software releases

<p align="center">
    <a href="https://www.python.org/">
        <img src="https://img.shields.io/badge/Python-3.12+-3776AB?style=flat&logo=python&logoColor=white" alt="Python"/>
    </a>
    <a href="https://cryptography.io/">
        <img src="https://img.shields.io/badge/cryptography-50.0.2-306998?style=flat&logo=python&logoColor=white" alt="cryptography"/>
    </a>
    <a href="https://www.docker.com/">
        <img src="https://img.shields.io/badge/Docker-Image-2496ED?style=flat&logo=docker&logoColor=white" alt="Docker"/>
    </a>
    <a href="https://github.com/features/actions">
        <img src="https://img.shields.io/badge/GitHub_Actions-CI%2FCD-2088FF?style=flat&logo=githubactions&logoColor=white" alt="GitHub Actions"/>
    </a>
    <a href="https://docs.pytest.org/">
        <img src="https://img.shields.io/badge/pytest-9.2.0-0A9EDC?style=flat&logo=pytest&logoColor=white" alt="pytest"/>
    </a>
</p>

Your release just rolled off the build line, warm and shiny. But how will the world know it's *really* yours and not a sneaky look-alike swapped in somewhere between your pipeline and their download button?

**Totally Awesome CI/CD Signing Tool Must Use 2026 (仮)** stamps every release with a digital signature (RSA-PSS, ECDSA P-256 or Ed25519, pick your poison) and checks it against a list of keys *you* chose to trust. One flipped byte, one unknown key, one suspicious version number, and **Totally Awesome CI/CD Signing Tool Must Use 2026 (仮)** says no, loudly, with a non-zero exit code your pipeline can't ignore. It ships as a container, so your CI just pulls it and gets signing.

P.S. We are open to suggestion on the software name, hence the (仮) meaning temporary :D

Created by Group 4 for Tugas 3 of IF4020 Kriptografi (2026/2027), Institut Teknologi Bandung.

---

## Table of Contents

- [Features](#features)
- [Program Structure](#program-structure)
- [Technology and Frameworks](#technology-and-frameworks)
- [Program Requirements](#program-requirements)
- [Installation](#installation)
- [Running the Program](#running-the-program)
- [Cryptography Algorithms](#cryptography-algorithms)
- [File Formats](#file-formats)
- [Testing](#testing)
- [Creators](#creators)

---

## Features

1. **Keys**
    - Generate RSA-3072, ECDSA P-256 or Ed25519 key pairs (PKCS8 / SPKI PEM)
    - Fingerprint every public key as `keyid = SHA-256(DER SPKI)`
2. **Signing**
    - Hash the release artifact, write a canonical release manifest, sign it, and pack both into a bundle
3. **Verification**
    - Check format, algorithm, key trust, signature, metadata and artifact in a fixed order, and stop at the first failure
    - Human-readable result or one-line JSON (`--json`) with distinct exit codes for CI
4. **Trust store**
    - Add, list and remove trusted public keys, each limited to the packages it may sign
5. **Signed SBOM (bonus)**
    - Verify a release and its signed SBOM together, and check the SBOM is bound to the release's SHA-256
6. **Distribution**
    - Published container image, pinned by digest, that runs without network access
    - Consumer CI/CD pipeline that signs, verifies and only then "deploys"

---

## Program Structure

The tool lives in `src/tacstmu/`; everything else are tests, evidence and CI configuration.

1. `src/tacstmu/core/`: shared building blocks (constants, outcome statuses, strict JSON, strict Base64, artifact hashing)
2. `src/tacstmu/crypto/`: key handling and the three signature algorithms
3. `src/tacstmu/release/`: manifest, bundle, sign and verify flows, trust store, SBOM
4. `src/tacstmu/cli.py`: the command-line interface
5. `tests/`: unit tests, scenario/interop/benchmark runners, test keys and saved results
6. `ci/`: reference copy of the consumer pipeline's configuration
7. `Dockerfile`, `.github/workflows/`: container image and its publishing workflow

```bash
.
├── Dockerfile
├── pyproject.toml
├── .github/workflows/publish-dockerhub.yml
├── ci/
│   ├── consumer/          # consumer workflow + scripts (reference copy)
│   ├── keys/              # pipeline public keys
│   └── trust.json         # pipeline trust store
├── src/tacstmu/
│   ├── cli.py
│   ├── core/              # constants, outcomes, jsoncheck, base64, artifact
│   ├── crypto/            # keys, signature
│   └── release/           # manifest, bundle, signing, verification, trust, sbom
└── tests/
    ├── unit/              # pytest unit tests
    ├── scenarios/run.py   # U01–U14
    ├── interop/run.py     # OpenSSL cross-checks
    ├── benchmarks/run.py  # performance measurements
    ├── keys/              # test-only key pairs
    └── results/           # saved evidence: scenarios, interop, benchmarks, ci
```

---

## Technology and Frameworks

**Program**
- **Python** – implementation language of the tool
- **cryptography** – RSA-PSS, ECDSA, Ed25519, SHA-256 and PEM/DER key encoding
- **argparse** (standard library) – command-line interface

**Distribution**
- **Docker** – container image the CI/CD pipeline pulls and runs
- **Docker Hub** – public registry hosting the image
- **GitHub Actions** – builds and publishes the image, and runs the consumer pipeline

**Testing**
- **pytest** – unit tests
- **OpenSSL** – independent implementation for the interop checks

---

## Program Requirements

- **Python 3.12 or newer** – to install and run the tool locally
- **cryptography 50.0.2** – the only runtime dependency, installed automatically
- **pytest 9.2.0** – development dependency for the unit tests, installed with `[dev]`
- **Docker** – to run the published image
- **OpenSSL 3.x** – only for the interop checks

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/Staryo40/tugas-3-if4020-kripto.git
cd tugas-3-if4020-kripto
```

### 2. Create a virtual environment and install
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

What `pip install -e ".[dev]"` does:

- `.` installs the project in the current folder, as described by `pyproject.toml` (including its dependency, `cryptography`).
- `-e` (editable) links the installed package to the source in `src/`, so code changes take effect immediately without reinstalling.
- `[dev]` also installs the optional development tools listed under `dev` (currently `pytest`).

---

## Running the Program

### Run with Docker

The image is available on [Docker Hub](https://hub.docker.com/r/rizalks/tacstmu).

| Ver | Repository tag | Image tag | Image digest |
|---|---|---|---|
| `0.1.0` | `v0.1.0` | `rizalks/tacstmu:0.1.0` | `sha256:ce601a5f0f21667f322456ed2dd1610fa7f3418b7725b5a7a903f5f89594b4d3` |

Pull the exact digest and check it runs:

```bash
IMAGE=rizalks/tacstmu@sha256:ce601a5f0f21667f322456ed2dd1610fa7f3418b7725b5a7a903f5f89594b4d3
docker pull "$IMAGE"
docker run --rm --network none "$IMAGE" --version
docker run --rm --network none "$IMAGE" --help
```

Inputs are read through bind mounts and outputs are written to a mounted folder. For example, signing `dist/contoh-app.zip`:

```bash
mkdir -p out
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" \
  -v "$PWD/out:/output" \
  -v "$PWD/keys/publisher.key.pem:/run/signing.key.pem:ro" \
  "$IMAGE" sign --file /input/contoh-app.zip --package contoh-app --version 1.0.0 \
  --key /run/signing.key.pem --out /output/release.json
```

### Run Locally

After [Installation](#installation), the `tacstmu` command is available in the virtual environment:

```bash
tacstmu --help
python -m tacstmu --help
```

### Command Reference

Generate a key pair (writes `keys/publisher.key.pem` and `keys/publisher.pub.pem`, prints the keyid):

```bash
tacstmu keygen --algorithm ed25519 --out keys/publisher
```

Trust the public key for a package, then list and remove trusted keys:

```bash
tacstmu trust add --key keys/publisher.pub.pem --package contoh-app --store trust.json
tacstmu trust list --store trust.json
tacstmu trust remove --keyid <keyid> --store trust.json
```

Sign an artifact into a bundle (`--force` overwrites an existing bundle):

```bash
tacstmu sign --file contoh-app.zip --package contoh-app --version 1.0.0 \
  --key keys/publisher.key.pem --out release.json
```

Verify it, as text or as one-line JSON:

```bash
tacstmu verify --file contoh-app.zip --bundle release.json --trust-store trust.json \
  --package contoh-app --version 1.0.0
tacstmu verify --file contoh-app.zip --bundle release.json --trust-store trust.json \
  --package contoh-app --version 1.0.0 --json
```

Sign an SBOM as its own artifact, then verify the release and the SBOM together (bonus):

```bash
tacstmu sign --file sbom.json --package contoh-app-sbom --version 1.0.0 \
  --key keys/publisher.key.pem --out sbom-bundle.json
tacstmu trust add --key keys/publisher.pub.pem --package contoh-app-sbom --store trust.json
tacstmu verify-release --file contoh-app.zip --bundle release.json \
  --sbom sbom.json --sbom-bundle sbom-bundle.json --trust-store trust.json \
  --package contoh-app --version 1.0.0 --sbom-package contoh-app-sbom --sbom-version 1.0.0 --json
```

`--algorithm` accepts one of `rsa-pss-sha256`, `ecdsa-p256-sha256` or `ed25519`. Commands never prompt; a missing option or an output conflict is an error with exit code 2.

### Run in a CI/CD Pipeline

The pipeline that *uses* the published image lives in its own consumer repository, the way a real project that depends on tacstmu would: [rizalkhairan/software-release-cicd-test](https://github.com/rizalkhairan/software-release-cicd-test).

For every algorithm it packages the project, pulls the image by digest, writes the signing key from a CI secret to a temporary file, signs the release, runs `verify --json`, and writes a deployment marker only when verification passes. The minimal form of each step on a Linux runner:

```bash
set -eu
: "${IMAGE:?mandatory}"
: "${SIGNING_KEY_FILE:?mandatory}"
trap 'rm -f "$SIGNING_KEY_FILE"' 0
mkdir -p out
docker pull "$IMAGE"

docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" -v "$PWD/out:/output" \
  -v "$SIGNING_KEY_FILE:/run/signing.key.pem:ro" \
  "$IMAGE" sign --file /input/contoh-app.zip --package contoh-app --version 1.0.0 \
  --key /run/signing.key.pem --out /output/release.json

docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" -v "$PWD/out:/output:ro" -v "$PWD/ci/trust.json:/trust.json:ro" \
  "$IMAGE" verify --file /input/contoh-app.zip --bundle /output/release.json \
  --trust-store /trust.json --package contoh-app --version 1.0.0 --json > out/verification.json
```

A failed `verify` exits non-zero, so `set -e` stops the job before any deployment step.

A reference copy of the consumer repository's configuration is kept in `ci/`, with the same layout:

| Path | What |
|---|---|
| `ci/consumer/consumer-tests.yml` | The workflow (in the consumer repo it sits in `.github/workflows/`; here it is outside, so it does not run) |
| `ci/consumer/run_scenarios.py` | Runs C01–C05 against the pulled image and records the evidence |
| `ci/consumer/prepare_keys.py` | One-time local setup of the test keys and trust store, never run in the workflow |
| `ci/consumer/image.txt` | The image reference the pipeline pins, by digest |
| `ci/trust.json`, `ci/keys/` | The pipeline's trust store and public test keys; the private keys exist only as CI secrets |

To run the tests and see their results, see [Testing](#testing).

---

## Cryptography Algorithms

All three algorithms come from [`cryptography` 50.0.2](https://cryptography.io/en/latest/). Key generation, the RSA-PSS salt and the ECDSA nonce use the operating system's secure random generator through the library; Ed25519 signing is deterministic by design.

| Profile | Parameters | Library API | Signature |
|---|---|---|---|
| `rsa-pss-sha256` | RSA 3072 bit, e = 65537; RSASSA-PSS, SHA-256, MGF1-SHA-256, salt 32 bytes | [`rsa.generate_private_key(65537, 3072)`](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/), `key.sign(M, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())` | 384 bytes |
| `ecdsa-p256-sha256` | NIST P-256, SHA-256, random nonce | [`ec.generate_private_key(ec.SECP256R1())`](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/), `key.sign(M, ec.ECDSA(hashes.SHA256()))`, DER converted with `decode_dss_signature` / `encode_dss_signature` | 64 bytes, `r ‖ s`, 32 bytes each, big-endian |
| `ed25519` | Ed25519 (PureEdDSA, RFC 8032), no pre-hash | [`Ed25519PrivateKey.generate()`](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/), `key.sign(M)` | 64 bytes |

`M` is the manifest bytes. For RSA and ECDSA the library applies SHA-256 to `M` exactly once; for Ed25519, `M` is passed as it is. Keys are written and read with [`serialization`](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/) as PKCS8 / SPKI.

---

## File Formats

### Key files

| File | Format |
|---|---|
| `<prefix>.key.pem` | PKCS8 PEM, label `PRIVATE KEY`, unencrypted, file mode 0600 |
| `<prefix>.pub.pem` | SPKI PEM, label `PUBLIC KEY`; P-256 points uncompressed, Ed25519 per RFC 8410 |
| keyid | `hex_lower(SHA-256(DER SPKI))` from the re-exported key, so PEM line endings or wrapping never change it |

### Release manifest

The signed message. Canonical JSON: this exact field order, no whitespace, no trailing newline, ASCII only, at most 16 KiB.

```json
{"schema":"minisign-manifest/v1","package":"contoh-app","version":"1.0.0","algorithm":"ed25519","keyid":"<64 hex>","artifact":{"name":"contoh-app.zip","size":1048576,"sha256":"<64 hex>"}}
```

### Bundle

What is published next to the artifact, at most 64 KiB. Field order and whitespace are free; both values are standard Base64 with padding.

```json
{
  "schema": "minisign-bundle/v1",
  "manifest_b64": "<Base64 of the manifest bytes>",
  "signature_b64": "<Base64 of the signature bytes>"
}
```

### Trust store

```json
{
  "schema": "minisign-trust/v1",
  "keys": [
    {
      "keyid": "<64 hex>",
      "algorithm": "ed25519",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
      "packages": ["contoh-app"]
    }
  ]
}
```

### Verification result and exit codes

`verify --json` prints one JSON object followed by one newline. `algorithm`, `keyid`, `package` and `version` are `null` until they can be read from the manifest.

```json
{"valid": true, "status": "OK", "message": "Signature, metadata, and artifact are valid.", "algorithm": "ed25519", "keyid": "<64 hex>", "package": "contoh-app", "version": "1.0.0"}
```

Checks run in this order and stop at the first failure:

| No | Status if it fails | Check |
|---|---|---|
| 1 | `INPUT_ERROR` | All options given and all files readable |
| 2 | `FORMAT_ERROR` | Bundle, manifest and trust store structure, types, sizes, Base64 and canonical form |
| 3 | `UNSUPPORTED_ALGORITHM` | Manifest algorithm is one of the three profiles |
| 4 | `KEY_NOT_TRUSTED` | keyid in the trust store, same profile, allowed for the expected package |
| 5 | `INVALID_SIGNATURE` | Signature valid over the stored manifest bytes |
| 6 | `METADATA_MISMATCH` | Package, version and artifact name match what was expected |
| 7 | `ARTIFACT_MISMATCH` | Artifact size and SHA-256 match the manifest |
| 8 | `OK` | All checks passed |

| Exit code | Meaning |
|---|---|
| 0 | Success; for `verify`, status `OK` |
| 1 | Verification rejected (any status from 2 to 7) |
| 2 | Usage, I/O or environment error (`INPUT_ERROR`), and any failure of a command other than `verify` |

### SBOM (bonus)

The SBOM is a JSON file signed like any other artifact, with the normal `sign` command and bundle format.

```json
{
  "schema": "tacstmu-sbom/v1",
  "release": {"sha256": "<SHA-256 of the release artifact>"},
  "components": [{"name": "cryptography", "version": "50.0.2"}]
}
```

`verify-release` options:

| Option | Type | Meaning |
|---|---|---|
| `--file` | path | Release artifact |
| `--bundle` | path | Release bundle |
| `--sbom` | path | SBOM file |
| `--sbom-bundle` | path | Bundle of the SBOM |
| `--trust-store` | path | Trust store used for both bundles |
| `--package`, `--version` | string | Expected release package and version |
| `--sbom-package`, `--sbom-version` | string | Expected SBOM package and version |
| `--json` | flag | Print the result as JSON |

It verifies the release first, then the SBOM, then checks that the SBOM's `release.sha256` equals the release artifact's SHA-256. Its JSON result:

| Field | Type | Meaning |
|---|---|---|
| `valid` | boolean | `true` only when everything passed |
| `status` | string | A verification status, or `SBOM_BINDING_MISMATCH` when the SBOM points to another release |
| `message` | string | Short explanation |
| `stage` | string | Where it stopped: `input`, `release`, `sbom`, `binding` or `complete` |
| `release`, `sbom` | object / null | The verification result of each bundle |
| `binding_valid` | boolean | Whether the SBOM is bound to the release |

Exit codes follow the table above: 0 when valid, 2 for `INPUT_ERROR`, 1 otherwise.

---

## Testing

### Running the Tests

Activate the virtual environment from [Installation](#installation) first. The scenario, interop and benchmark runners use the test-only key pairs committed in `tests/keys/`.

| Test set | Command | Extra setup | Results |
|---|---|---|---|
| Unit tests | `pytest` | – | terminal output |
| Scenarios U01–U14 | `python tests/scenarios/run.py` | – | `tests/results/scenarios/` |
| Interop | `python tests/interop/run.py` | `openssl` 3.x on `PATH` | `tests/results/interop/` |
| Benchmarks | `python tests/benchmarks/run.py` | ~2 minutes and ~300 MB free temporary space; keep the machine idle | `tests/results/benchmarks/` |
| CI integration C01–C05 | runs on GitHub in the [consumer repository](https://github.com/rizalkhairan/software-release-cicd-test) | needs that repository's signing-key secrets | `tests/results/ci/` |

Each runner rebuilds its results folder from scratch.

### Result Layout

Every scenario and interop test has its own folder:

| Entry | Content |
|---|---|
| `input/` | The input files: artifact, bundle, trust store (and for interop the extracted manifest and signature) |
| `log.json` | Every command that was run, in order, with its exit code, stdout and stderr |
| `expected.json` | The expected result and a one-line description |
| `actual.json` | The actual result and whether it passed |

`summary.json` in each results folder lists all tests with pass/fail. The runner scripts are the full definition of each test: they create the inputs, apply the change being tested, and run the commands recorded in `log.json`. A single step can be reproduced by running its `command` from inside the test's folder.

### Scenarios (U01–U14)

All 29 runs pass. U01 and U14 run for all three algorithms (U01 also for a text, a binary and an empty file); the others use Ed25519.

| ID | What it tests | Expected | Why the result satisfies it |
|---|---|---|---|
| U01 | Sign and verify a text, binary and empty file with the right key and metadata | `OK`, exit 0 | Every check passes for any file content, including zero bytes |
| U02 | One artifact byte changed, same size and name | `ARTIFACT_MISMATCH`, exit 1 | The signature still matches the manifest, but the artifact's SHA-256 no longer matches it |
| U03 | One artifact byte added or removed | `ARTIFACT_MISMATCH`, exit 1 | The artifact's size and SHA-256 differ from the signed values |
| U04 | Manifest version changed (still canonical), old signature kept | `INVALID_SIGNATURE`, exit 1 | The signature was made over different bytes, so it does not verify |
| U05 | One signature bit flipped, same length, valid Base64 | `INVALID_SIGNATURE`, exit 1 | The format is valid, but the signature no longer verifies |
| U06 | Empty trust store, or publisher key removed | `KEY_NOT_TRUSTED`, exit 1 | No trusted key matches the manifest's keyid |
| U07 | Key trusted only for another package | `KEY_NOT_TRUSTED`, exit 1 | The key exists but is not allowed to sign the expected package |
| U08 | Valid bundle, different expected version | `METADATA_MISMATCH`, exit 1 | The signature is valid, but the signed version is not the one requested |
| U09 | Artifact renamed, content unchanged | `METADATA_MISMATCH`, exit 1 | The file's name no longer equals the signed `artifact.name` |
| U10 | Duplicate field, wrong type, invalid Base64, manifest over 16 KiB (each separately) | `FORMAT_ERROR`, exit 1 | Each input is malformed and is rejected before any key or signature is used |
| U11 | Unsupported algorithm name in the manifest | `UNSUPPORTED_ALGORITHM`, exit 1 | The value is not one of the three profiles |
| U12 | Signed by another key of the same profile, not trusted | `KEY_NOT_TRUSTED`, exit 1 | A valid signature alone is not enough; the key must be in the trust store |
| U13 | Bundle whitespace and field order changed, Base64 strings kept | `OK`, exit 0 | Only the signed manifest bytes matter; the bundle's layout is free |
| U14 | Identical manifest signed twice with the same key | Both verify; identical only for Ed25519 | Ed25519 is deterministic; RSA-PSS uses a random salt and ECDSA a random nonce, so their two signatures differ |

### Interop

All 6 cases pass against OpenSSL 3.5.9 (an independent implementation; the tool itself uses the OpenSSL build bundled with `cryptography`).

| Algorithm | tacstmu → OpenSSL | OpenSSL → tacstmu |
|---|---|---|
| RSA-PSS | OpenSSL verifies our signature with PSS, MGF1-SHA-256 and salt 32, and rejects it for a tampered manifest | tacstmu loads an OpenSSL key pair and verifies an OpenSSL signature: `OK` |
| ECDSA P-256 | OpenSSL verifies our signature after converting `r ‖ s` to DER, and rejects a tampered manifest | OpenSSL's DER signature converted to `r ‖ s` verifies: `OK` |
| Ed25519 | OpenSSL verifies our signature, and rejects a tampered manifest | OpenSSL's signature verifies and is byte-identical to ours |

This shows the signatures and key files follow the standards rather than one library's conventions.

### Benchmarks

Measured with a monotonic clock (`time.perf_counter_ns`). Raw sign/verify and hashing use 5 warm-ups and 100 runs, end-to-end commands 5 warm-ups and 30 runs, key generation 10 runs. P95 is nearest-rank: the value at position `ceil(0.95 · n)` of the sorted samples. The same three artifacts (1 KiB, 1 MiB, 100 MiB of random bytes) are used for every algorithm.

| Median (ms) | RSA-PSS | ECDSA P-256 | Ed25519 |
|---|---|---|---|
| Key generation | 112.02 | 0.011 | 0.024 |
| Raw sign (manifest) | 0.54 | 0.018 | 0.025 |
| Raw verify (manifest) | 0.034 | 0.049 | 0.079 |
| End-to-end sign, 1 KiB / 100 MiB | 232.7 / 289.7 | 131.1 / 213.6 | 146.8 / 194.2 |
| End-to-end verify, 1 KiB / 100 MiB | 146.0 / 195.7 | 161.1 / 196.5 | 148.4 / 196.8 |

SHA-256 of the artifact takes 0.008 ms (1 KiB), 0.78 ms (1 MiB) and 52.9 ms (100 MiB). End-to-end times include starting Python for every command.

| Size (bytes) | RSA-PSS | ECDSA P-256 | Ed25519 |
|---|---|---|---|
| Public key (DER) | 422 | 91 | 44 |
| Private key (DER) | 1794 | 138 | 48 |
| Signature | 384 | 64 | 64 |
| Bundle | 988 | 568 | 556 |

All samples are in `raw.csv`, medians and P95 in `summary.csv`, sizes in `sizes.csv`, and the hardware and software used in `environment.json`.

### CI Integration (C01–C05)

From [run 43581919825](https://github.com/rizalkhairan/software-release-cicd-test/actions/runs/43581919825) of the consumer pipeline, on a clean GitHub runner, using the image pulled by the digest above. All scenarios pass. The evidence, as downloaded from the run, is in `tests/results/ci/<algorithm>/`.

| ID | What it tests | Expected | Deployment marker |
|---|---|---|---|
| C01 | Pull the image, sign and verify a valid artifact (all three algorithms) | `OK`, exit 0 | present |
| C02 | One artifact byte changed after signing | `ARTIFACT_MISMATCH`, exit 1 | absent |
| C03 | Empty trust store | `KEY_NOT_TRUSTED`, exit 1 | absent |
| C04 | Artifact path does not exist | `INPUT_ERROR`, exit 2 | absent |
| C05 | CLI run with the runner's UID/GID, no TTY and `--network none` | `OK`, exit 0 | present |

Each scenario folder holds the commands, logs and real exit codes of `sign` and `verify`, the verification JSON, `expected.json` and `actual.json`, and `marker-evidence.txt`; `summary.json` records the image, UID/GID, network and TTY settings.

---

## Creators

<table>
    <tr align="left">
        <td><b>NIM</b></td>
        <td><b>Name</b></td>
        <td align="center"><b>GitHub</b></td>
    </tr>
    <tr align="left">
        <td>13523063</td>
        <td>Syahrizal Bani Khairan</td>
        <td align="center">
            <a href="https://github.com/rizalkhairan">
                <img src="https://github.com/rizalkhairan.png" width="48px;" alt=""/>
                <br/><sub><b>@rizalkhairan</b></sub>
            </a>
        </td>
    </tr>
    <tr align="left">
        <td>13523066</td>
        <td>Ghifary Komara Putra</td>
        <td align="center">
            <a href="https://github.com/Sanesasaha">
                <img src="https://github.com/Sanesasaha.png" width="48px;" alt=""/>
                <br/><sub><b>@Sanesasaha</b></sub>
            </a>
        </td>
    </tr>
    <tr align="left">
        <td>13523100</td>
        <td>Aryo Wisanggeni</td>
        <td align="center">
            <a href="https://github.com/Staryo40">
                <img src="https://github.com/Staryo40.png" width="48px;" alt=""/>
                <br/><sub><b>@Staryo40</b></sub>
            </a>
        </td>
    </tr>
</table>

# Totally Awesome CI/CD Signing Tool Must Use 2026 (仮)

Your release just rolled off the build line, warm and shiny. But how will the world know it's *really* yours and not a sneaky look-alike swapped in somewhere between your pipeline and their download button? 

**Totally Awesome CI/CD Signing Tool Must Use 2026 (仮)** stamps every release with a digital signature (RSA-PSS, ECDSA P-256 or Ed25519, pick your poison) and checks it against a list of keys *you* chose to trust. One
flipped byte, one unknown key, one suspicious version number, and **Totally Awesome CI/CD Signing Tool Must Use 2026 (仮)** says no, loudly, with a non-zero exit code your pipeline can't ignore. It ships as a container, so your CI just pulls it and gets signing. 

P.S. We are open to suggestion on the software name, hence the (仮) meaning temporary :D

## Published image

The image is available on [Docker Hub](https://hub.docker.com/r/rizalks/tacstmu).

| Ver | Tag | Image digest |
|---|---|---|
| `0.1.0` | `rizalks/tacstmu:0.1.0` | `sha256:ce601a5f0f21667f322456ed2dd1610fa7f3418b7725b5a7a903f5f89594b4d3` |


To pull and run the exact digest:

```sh
IMAGE=rizalks/tacstmu@sha256:ce601a5f0f21667f322456ed2dd1610fa7f3418b7725b5a7a903f5f89594b4d3
docker pull "$IMAGE"
docker run --rm --network none "$IMAGE" --version
docker run --rm --network none "$IMAGE" --help
```

## CI/CD pipeline

The pipeline that *uses* the published image lives in its own consumer repository, the way a
real project that depends on tacstmu would:
[rizalkhairan/software-release-cicd-test](https://github.com/rizalkhairan/software-release-cicd-test)
([latest run](https://github.com/rizalkhairan/software-release-cicd-test/actions/runs/43581919825)).

For every algorithm it packages the project, pulls the image by digest, signs the release with a
test key from a CI secret, runs `verify --json`, and writes a deployment marker only when
verification passes. The integration scenarios C01–C05 run there and upload their evidence
(commands, logs, exit codes, expected vs actual results, marker present/absent).

A reference copy of that repository's configuration is kept in `ci/`, with the same layout:

| Path | What |
|---|---|
| `ci/consumer/consumer-tests.yml` | The workflow (in the consumer repo it sits in `.github/workflows/`; here it is outside, so it does not run) |
| `ci/consumer/run_scenarios.py` | Runs C01–C05 against the pulled image and records the evidence |
| `ci/consumer/prepare_keys.py` | One-time local setup of the test keys and trust store, never run in the workflow |
| `ci/consumer/image.txt` | The image reference the pipeline pins, by digest |
| `ci/trust.json`, `ci/keys/` | The pipeline's trust store and public test keys; the private keys exist only as CI secrets |

## Setup and running locally

Requires Python 3.12 or newer.

```sh
python3 -m venv .venv          # create an isolated environment for this project
source .venv/bin/activate      # use it in this shell (Windows: .venv\Scripts\activate)
pip install -e ".[dev]"        # install tacstmu + its dependencies + dev tools
```

What `pip install -e ".[dev]"` does:

- `.` installs the project in the current folder, as described by `pyproject.toml`
  (including its dependency, `cryptography`).
- `-e` (editable) links the installed package to the source in `src/`, so code changes take
  effect immediately without reinstalling.
- `[dev]` also installs the optional development tools listed under `dev` (currently `pytest`).

Run the tool, either through the installed command or as a module:

```sh
tacstmu --help
python -m tacstmu --help
```

Run the tests:

```sh
pytest
```

## Running the test scenarios

The security scenarios U01–U14 run through the real CLI, using the test-only keypairs in
`tests/keys/`:

```sh
python tests/scenarios/run.py
```

Each scenario gets its own folder in `tests/results/scenarios/` (for example
`U05-signature-bit-flipped/`) holding the input files (`input/`), every command that was run
(`commands.json`), their output and real exit codes (`*.stdout.log`, `*.stderr.log`,
`*.exit-code.txt`), and the expected and actual results (`expected.json`, `actual.json`).
`summary.json` lists all scenarios with pass/fail. U01 and U14 run for all three algorithms,
the others with Ed25519. The results folder is rebuilt on every run.

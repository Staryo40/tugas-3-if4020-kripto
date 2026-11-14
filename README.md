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

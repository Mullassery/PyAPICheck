# Contributing to pyapicheck

The core logic (parsing, classification, scoring, graph, policy) lives in
Rust (`core/`); `bindings/` is a thin PyO3 layer over it, and
`python/pyapicheck/` is the Python CLI/SDK wrapper. Most contributions
touch `core/` — start there unless you're specifically working on the CLI
surface.

## Dev setup

Requires a Rust toolchain (stable) and Python 3.9+. This project uses
[uv](https://github.com/astral-sh/uv) for the Python virtualenv, but plain
`venv`/`pip` works too.

```bash
uv venv .venv --python 3.12
source .venv/bin/activate
uv pip install maturin pytest

# Build the Rust extension and install it into .venv in one step
maturin develop --release
```

## Running the checks

These are the exact commands CI runs (`.github/workflows/ci.yml`) — run
them before opening a PR:

```bash
# Rust: unit + integration tests (67 unit + 7 integration as of this
# writing — core/tests/discover_test.rs is the integration suite)
cargo test -p pyapicheck-core

# Lint (CI runs this with -D warnings, i.e. any clippy warning fails CI)
cargo clippy --all-targets -- -D warnings

# Formatting
cargo fmt --check

# Python: requires the extension built into .venv first (`maturin develop`)
pytest tests/ -v
```

Two of `core`'s test modules (`core/src/db.rs`, `core/src/graph.rs`) have
integration tests against a real Postgres (+ Apache AGE for the graph
tests). They **skip themselves** (print `skipping: DATABASE_URL not set`,
not a failure) when `DATABASE_URL` is unset, so a normal local `cargo
test` run won't exercise them. To run them for real:

```bash
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=test -e POSTGRES_DB=pyapicheck apache/age
DATABASE_URL=postgres://postgres:test@localhost:5432/pyapicheck cargo test -p pyapicheck-core
```

`bindings/` (the PyO3 cdylib) is excluded from the cargo workspace's
default members — it only links correctly through maturin's build, not a
plain `cargo build`. Build/test it via `maturin develop`/`maturin build`,
not `cargo build -p pyapicheck-bindings`.

## Project conventions

- **Every risk/policy finding must name the specific, checkable reason it
  fired.** No black-box scores, no "trust me" heuristics. If you're adding
  a new finding type, it needs a named factor and a human-readable reason
  string, matching the existing pattern in `core/src/risk.rs`.
- **Don't fake integration coverage.** Where this project claims something
  was "verified against a real X" (a real Postgres, a real Envoy, a real
  MCP JSON-RPC handshake), that means an actual running instance was
  exercised, not a mock that looks plausible. See `ROADMAP.md` for the
  standard this repo holds itself to — new work should match it.
- **No stub code that pretends to work.** If a feature is incomplete,
  either don't merge it, or clearly gate/document it as incomplete (see
  `ROADMAP_HONEST.md`) — don't ship a function that silently returns
  fake/empty data.
- Rust code must pass `cargo clippy -- -D warnings` and `cargo fmt`;
  there's no separate style guide beyond that.

## Where to look first

- `ROADMAP.md` — the phase-by-phase engineering plan, including what's
  explicitly deferred and why. Read this before proposing new scope.
- `ROADMAP_HONEST.md` — current bugs, tech debt, and untested paths. If
  you're looking for something to work on, this is the honest list.

## Reporting issues / proposing features

Use the GitHub issue templates (bug report / feature request). Include
the exact command you ran and the exact output for bug reports — this
project's whole premise is that findings should be checkable, and bug
reports should be too.

## License

By contributing, you agree your contributions are licensed under the
project's [Apache License 2.0](LICENSE).

# Honest Status

This file is the quick-scan companion to `ROADMAP.md`. `ROADMAP.md` is the
detailed, phase-by-phase engineering plan (already written with its own
honesty notes and scope cuts — read it for the *why*). This file exists
for org-wide consistency: a flat, 4-bucket list of what's actually true
right now, as of this audit (2026-09-19), verified by running the real
commands (not by reading code and assuming).

## What was actually run this session

```
cargo test -p pyapicheck-core          → 67 unit + 7 integration tests, all pass
cargo clippy --all-targets -- -D warnings → clean, no warnings
cargo fmt --check                      → clean
pytest tests/ -v                       → 8/8 pass (after `maturin develop --release`)
maturin build --release                → succeeds, produces a wheel
cargo audit                            → NOT run (this sandbox has no network
                                          access to fetch the RustSec advisory
                                          DB); newly added as a CI job this
                                          session, unverified until it runs on
                                          a real GitHub Actions runner
```

`core/src/db.rs` and `core/src/graph.rs` integration tests require
`DATABASE_URL` (a real Postgres+AGE instance) — they skip themselves
(print `skipping: DATABASE_URL not set`) rather than fail when it's
unset, which is what happened in this local run. CI sets `DATABASE_URL`
against a real `apache/age` container, so those tests do run there — but
I did not spin up that container myself this session to re-verify it live
locally; I'm relying on the CI job configuration being correct, which I
did read line-by-line.

I could not independently re-check that the live GitHub Actions workflow
is actually green right now, or that the PyPI v0.7.0 release genuinely
matches this repo (both `gh api` and general outbound network access
timed out from this sandbox). The README's claim of CI-green-through-
Phase-7 and PyPI-matches-exactly predates this session and was not
re-verified by me — treat it as an existing, previously-made claim, not
something I confirmed today.

---

## Bucket 1: Built, not independently tested (by me, this session)

- **11 of 12 CLI subcommands have zero Python-level test coverage.**
  `tests/test_remediate.py` is the only Python test file and it only
  covers `remediate` (library function + CLI). `discover`, `diff`,
  `report`, `baseline`, `policies validate/recommend/diff/emit-envoy`, and
  `graph load-mcp/add-agent/reachable/blast-radius` (`python/pyapicheck/
  cli.py`, ~653 lines, 12 subcommands total per `add_parser` calls) have
  Rust-level coverage of the underlying logic but no test that exercises
  the actual CLI argument parsing/output formatting for those commands.
- The `graph` (Postgres+AGE) and `db` (Postgres persistence) integration
  tests are real and do run in CI against a live container — but I did
  not run them myself this session (no local Postgres). I'm trusting the
  CI config, not a fresh confirmation.
- `emit-envoy`'s claim of being checked against a live `envoyproxy/envoy`
  container (403 checks) is a claim from a prior commit's message/README
  text, not something re-verified by me this session — I read the code in
  `core/src/enforcement.rs` and it's consistent with that claim, but I did
  not spin up Envoy to re-check it.

## Bucket 2: Not built / does not exist

- **Phase 5 (AI Security Analyst)** — the product's stated
  differentiator. Zero code exists for it. `ROADMAP.md` explicitly gates
  further "analyst" work behind a citation-verifiability bar that hasn't
  been attempted yet.
- **No live enforcement.** `emit-envoy` produces a YAML snippet; nothing
  in this repo applies it to a running Envoy, and there is no Kong (or
  any other gateway) integration at all.
- **No git tags / GitHub Releases exist for any shipped version**
  (`v0.1.0` through `v0.7.0` only exist as version-string bumps in
  `Cargo.toml`/`pyproject.toml` inside commits — `git tag -l` returns
  nothing). If PyPI releases were cut from these commits, there's no
  git-level record tying a PyPI version to a specific commit SHA.
- **No CODEOWNERS, no branch protection visible from this repo's files**
  (can't be fully confirmed from the local clone — GitHub branch
  protection is a server-side setting, not a file).

## Bucket 3: CI gaps (found and partly fixed this session)

Fixed this session:
- **CI built the Python wheel but never ran the Python test suite against
  it.** `maturin-build` ran `maturin build --release` and stopped —
  `tests/test_remediate.py` was never executed in CI. Fixed: the job now
  installs the built wheel + pytest and runs `pytest tests/ -v`.
- **No dependency-vulnerability scanning at all.** Added a `security` job
  running `cargo audit` against the RustSec advisory database. This is
  new and **unverified** — see the "what was actually run" section above.
  If it turns up a real advisory on the first run (plausible — `ring`,
  `rustls`, `sqlx`, `tokio`, `cedar-policy` are all present in
  `Cargo.lock` and haven't been audited before), that's a genuine finding
  to triage, not a false positive to silence.
- **No Dependabot config existed.** Added `.github/dependabot.yml`
  (cargo, pip, github-actions ecosystems, weekly).

Still open:
- CI only targets `ubuntu-latest` — no macOS/Windows wheel build or test
  matrix, so a Rust/PyO3 change that happens to only break on macOS or
  Windows (e.g. a path-separator bug) wouldn't be caught. PyPI's actual
  published wheels' platform coverage was not verified this session (no
  network to check PyPI).
- No `cargo audit`/dependency-scan step existed before this session at
  all — the finding above from Bucket 1/3 also means: nobody has ever
  checked whether any of this project's Rust dependencies have a known
  CVE. That check exists now but has not actually run yet.

## Bucket 4: Features that exist but are explicitly not fully functional

(These are all *disclosed by the project's own README/ROADMAP already* —
restated here for the 4-bucket scan, not new findings.)

- **`emit-envoy` output is an artifact, not enforcement.** It generates a
  config snippet; nothing wires it into a live request path.
- **`policies diff`/`recommend` are advisory-only.** Cedar has no native
  "require approval" effect; `require_approval` findings are represented
  as `forbid` + an annotation a human has to read and act on.
- **BOLA-shaped detection has no per-record ownership cross-reference**
  (documented scope cut in `ROADMAP.md` Phase 4.3) — it flags sequential-
  ID access patterns, but can't tell you whether the accessed IDs were
  actually owned by someone else, because no per-record ownership data
  exists anywhere in this project to check against.
- **Response-shape drift detection does not exist** — `lifecycle.rs`
  works off access-log status codes, which carry no response body, so
  there's structurally nothing to diff a schema against (Phase 2 honesty
  note in `ROADMAP.md`).

---

## Technical debt (concrete, with file:line, not fixed this session — flagged for follow-up)

1. **`serde_yaml` is a deprecated, archived crate**
   (`Cargo.lock`: `serde_yaml 0.9.34+deprecated` — the `+deprecated` in
   the resolved version string is upstream's own signal that the crate is
   no longer maintained). It's used directly across
   `core/src/lib.rs`, `core/src/enforcement.rs`, `core/src/remediate.rs`,
   and — most load-bearingly — `core/src/text_patch.rs` (595 lines,
   format-preserving YAML patching, the whole mechanism `remediate
   --apply` depends on). Migrating off it is real, non-trivial work
   (there's no drop-in replacement with the same format-preservation
   guarantees `text_patch.rs` relies on) — **this warrants a dedicated
   follow-up session**, not a quick swap.
2. **`pyo3` is pinned to `0.22`** (`bindings/Cargo.toml`: `pyo3 = { version
   = "0.22", features = ["abi3-py39"] }`; `Cargo.lock` resolves
   `pyo3 0.22.6`). Newer pyo3 minor versions exist upstream; I did not
   verify exactly how far behind this is (no network access this
   session) or whether upgrading is a breaking change for this project's
   binding surface — flagged for a follow-up to check, not fixed here.
3. **Duplicated fixture file**: `examples/sample-openapi.yaml` and
   `core/tests/fixtures/sample-openapi.yaml` are byte-for-byte identical
   (confirmed via `diff` this session). Minor — a future edit to one and
   not the other would silently desync the README's example from what
   the test suite actually exercises. Low priority, safe to leave as-is
   or symlink in a future cleanup pass.
4. **No version-to-commit traceability** (see Bucket 2 above) — if this
   ever needs a security disclosure tied to "which exact commit is PyPI
   version X," there is currently no way to answer that from git alone.
5. **CI has no OS/Python-version matrix** (see Bucket 3) — single
   `ubuntu-latest` + Python 3.12 job covers everything.
6. **Thin Python test coverage relative to the Rust core** (Bucket 1) —
   worth a dedicated pass to add CLI-level tests for the other 11
   subcommands, especially `remediate --apply`'s disk-write path (already
   tested) versus the DB-writing (`--db-url`) and graph-mutating commands,
   which have no Python-level test at all (only Rust-level coverage of
   the underlying `core` functions they call).

None of the above are exploitable vulnerabilities as far as this audit
could determine (no network access to actually run `cargo audit` this
session is itself the gap — item 3 in Bucket 3). Items 1 and 2 are the
ones that most warrant a dedicated follow-up session; items 3–6 are minor
and can be picked up opportunistically.

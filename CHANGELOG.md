# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Entries below are reconstructed from git history and `ROADMAP.md`'s
phase records, not a changelog that was maintained turn-by-turn as
commits landed. **No git tags exist for any of these versions** — version
numbers come from `Cargo.toml`/`pyproject.toml` bumps in the commits
noted, not from `git tag`/GitHub Releases. See `ROADMAP_HONEST.md` for
that gap.

## [Unreleased]

- CI: added a `security` job (`cargo audit` against the RustSec advisory
  database) and fixed a gap where the `maturin-build` job built the
  Python wheel but never ran the Python test suite against it — it now
  installs the built wheel and runs `pytest tests/ -v`.
- Added `.github/dependabot.yml` (cargo, pip, github-actions ecosystems).
- Added `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`,
  `ROADMAP_HONEST.md`, and GitHub issue/PR templates.
- `.gitignore`: added `.pytest_cache/`, `.env`, `.idea/`, `.vscode/`;
  broadened the egg-info pattern.

## [0.7.0] — 2026-08-30

### Added
- Phase 7: Envoy `envoy.filters.http.rbac` enforcement-artifact generation
  from Cedar `forbid` policies (`core/src/enforcement.rs`,
  `pyapicheck policies emit-envoy`). Schema verified against a real
  `envoyproxy/envoy:v1.31` Docker container (`envoy --mode validate` plus
  a live 403 check) per the commit implementing it.

## [0.6.0] — 2026-08-30

### Added
- Phase 6: agent/MCP policy via Cedar — real `cedar-policy` crate
  integration, policy recommendations from Phase 4 findings, and
  policy-drift detection against an existing policy file
  (`core/src/policy.rs`, `pyapicheck policies validate/recommend/diff`).

## [0.5.0] — 2026-08-30

### Added
- Phase 4: behavioral baselining — per-identity traffic baselines,
  sequential-ID (BOLA-shaped) access detection, and first-time-observed-
  operation detection (`core/src/baseline.rs`, `pyapicheck baseline`).

## [0.4.0] — 2026-08-27

### Added
- Phase 3: security graph (Postgres + Apache AGE) and MCP server
  discovery, including live stdio JSON-RPC tool enumeration
  (`core/src/graph.rs`, `core/src/mcp.rs`, `pyapicheck graph ...`).

## [0.3.0] — 2026-08-27

### Added
- Phase 2: gateway access-log ingestion, observed-vs-declared
  (shadow/zombie endpoint) classification, and optional PostgreSQL
  persistence (`core/src/traffic.rs`, `core/src/lifecycle.rs`,
  `core/src/db.rs`, `pyapicheck report`).

## [0.2.0] — 2026-08-27

### Added
- Phase 1: directory/repo-wide spec discovery, OpenAPI drift detection
  (`pyapicheck diff`), and Postman Collection v2.1 import
  (`core/src/discover_dir.rs`, `core/src/drift.rs`, `core/src/postman.rs`).
- Automated remediation (`pyapicheck remediate`, commit `c8baab8`):
  safe, mechanical fixes for `no_auth` and `missing_metadata` findings
  (`core/src/remediate.rs`, `core/src/text_patch.rs`). Landed in the same
  version bump as Phase 1, ahead of Phase 1's own commit.
- CI workflow added (`cargo test`/`clippy`/`fmt` for `core`, `maturin
  build`), including a fix for the maturin sdist omitting `LICENSE`.

## [0.1.0] — 2026-08-16

### Added
- Initial release: OpenAPI 3.x discovery, keyword-based sensitive-field
  classification, and a transparent risk engine where every score traces
  to a named, human-readable factor (`core/src/openapi.rs`,
  `core/src/classify.rs`, `core/src/risk.rs`). PyO3 bindings + the
  `pyapicheck` CLI (`discover`, `--json`, `--fail-on-high`).

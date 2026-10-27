# PyAPICheck - Systems Design Audit

**Audit Date:** 2026-10-26  
**Repository Path:** /Users/georgimullassery/Desktop/Projects/pyapicheck  
**Type:** Read-only systems design audit  

## 1. Overview

PyAPICheck is an API security risk analysis tool that discovers API surfaces from OpenAPI specs/Postman collections, classifies sensitive data, scores risks with traceable reasoning (every risk score cites named factors), and cross-references with traffic for drift/zombie/shadow detection. It includes MCP/agent security graph modeling, behavioral baselining, Cedar policy generation/validation, and Envoy artifact emission. Built with a Rust core (`core/`) and PyO3 bindings (`bindings/`), exposed as a Python package (`python/pyapicheck/`) via maturin with a CLI entrypoint.

**Key Characteristics:**
- Hybrid Rust/Python architecture (maturin build)
- Evidence-backed findings (traceable risk factors)
- Advisory-first (does not enforce policies)
- OpenAPI-first focus on authorization/business-logic gaps

## 2. Architecture & Design

### 2.1 High-Level Structure
```
pyapicheck/
├── core/           # Rust core library (business logic)
│   ├── src/        # Core modules (discover, risk, classify, graph, policy, etc.)
│   ├── tests/      # Rust integration/unit tests
│   └── Cargo.toml
├── bindings/       # PyO3 bindings exposing core to Python
│   └── src/lib.rs
├── python/pyapicheck/ # Python wrapper/CLI
│   ├── cli.py      # CLI interface
│   ├── __init__.py # Public API
│   ├── active.py   # Schemathesis integration
│   ├── lint.py     # vacuum/Spectral adapters
│   ├── sarif.py    # SARIF output
│   └── investigate.py, remediate utilities
├── pyproject.toml  # Build config (maturin)
└── tests/          # Python tests
```

### 2.2 Core Components (Rust)

| Module | Purpose | Notes |
| --- | --- | --- |
| `model.rs` | Data models (Inventory, Endpoint, Risk, etc.) | Core domain types |
| `openapi.rs` | OpenAPI 3.0/3.1 parsing | Handles specs |
| `postman.rs` | Postman collection parsing | Alternative input |
| `discover_dir.rs` | Directory traversal for specs | Monorepo scanning |
| `classify.rs` | Sensitive field classification | Keyword-based heuristic |
| `risk.rs` | Risk scoring engine | Produces traceable factors |
| `drift.rs` | Spec diffing (added/removed/changed) | Compares inventories |
| `traffic.rs` | Access log parsing/reconciliation | Zombie/shadow detection |
| `lifecycle.rs` | Lifecycle classification | Active/zombie/shadow logic |
| `graph.rs` | Security graph modeling (MCP/agents) | Nodes/edges, reachability |
| `mcp.rs` | MCP config loading | For agent/tool graphs |
| `baseline.rs` | Behavioral baselining, BOLA detection | Per-identity patterns |
| `policy.rs` | Cedar policy operations | Validate/recommend/diff |
| `enforcement.rs` | Envoy config emission | Artifact generation |
| `remediate.rs` | Remediation plan generation | OpenAPI text patching |
| `text_patch.rs` | Text-level patching | Spec modification support |
| `db.rs` | Persistence support | Optional DB storage |

### 2.3 Python Layer
- Thin wrapper around `_core` (Rust) returning JSON-serializable dicts
- CLI with rich output (colorized), multiple output formats (JSON, SARIF)
- Integrations: Schemathesis (active testing), vacuum/Spectral (linting)
- Commands: discover, diff, report, baseline, graph-*, policies-*, remediate, investigate, lint, active

### 2.4 Design Principles Observed
- **Traceability**: Every risk has named factors with severities/descriptions
- **Separation of concerns**: Rust does heavy parsing/scoring/graph ops; Python handles CLI/integrations/output formatting
- **Extensibility**: Pluggable adapters (linters, active testing)
- **Advisory orientation**: Generates artifacts, doesn't enforce
- **Polyglot inputs**: OpenAPI, Postman, MCP configs, access logs

## 3. Dependencies

### 3.1 Rust (core/Cargo.toml, bindings/Cargo.toml)
Core likely uses: serde, serde_json, openapi parsing crates, regex/aho-corasick for classification, Cedar-related crates? (policy.rs suggests Cedar integration), graph algorithms, etc. Bindings use PyO3 with abi3 features.

### 3.2 Python (pyproject.toml)
- Runtime: Python >= 3.9
- Build: maturin >= 1.7
- Optional: schemathesis>=4.0 for active testing
- No heavy runtime deps in base install (relies on Rust extension)

### 3.3 External Tools (optional)
- vacuum (Go) or Spectral (Node) for linting
- Schemathesis for active testing

## 4. API Surface

### Python API (`pyapicheck.__init__`)
- `discover(spec_path)`, `discover_directory(dir)`, `discover_path(path)`
- `diff(old, new)`, `report(spec, access_log)`, `baseline(spec, hist_log, cur_log, known_agents=[])`
- `policies_validate(path)`, `policies_recommend(inventory_or_context)`, `policies_diff(old, new)`, `policies_emit_envoy(...)`
- `graph_load_mcp(mcp_config)`, `graph_add_agent(...)`, `graph_reachable(graph, start)`, `graph_blast_radius(...)`
- `remediate(spec_path, plan_or_findings)`, `persist(db_url, spec_path)`, `investigate(...)`
- `run_lint(...)`, `run_active_tests(...)`, `sarif` utilities

### CLI Commands (from cli.py)
discover, lint, active, diff, report, baseline, remediate, graph load-mcp/add-agent/reachable/blast-radius, policies validate/recommend/diff/emit-envoy, investigate, persist/sarif variants

## 5. Code Quality Observations

### Strengths
- Clear module boundaries
- Strong typing intent (Rust + Python type hints implied)
- Traceability as first-class design
- Comprehensive feature set covering discovery through policy generation
- Good separation between core logic and integrations
- Tests exist (Rust in core/tests, Python in tests/)
- Documentation-rich README with clear positioning vs related tools

### Potential Concerns (Read-only Observations)
- **Complexity**: Large feature surface (graph + baseline + policies + enforcement) increases maintenance burden
- **Heuristic classification**: Sensitive field detection is keyword-based (acknowledged as swappable)
- **Advisory-only**: Policy emission exists but no enforcement/runtime integration
- **Maturity**: Phase 5 (AI Security Analyst) not implemented per README
- **Rust core size**: Many modules suggest significant complexity in core
- **External tool dependencies**: Active/lint features require external binaries/CLIs

## 6. Testing

- Rust unit/integration tests in `core/tests/discover_test.rs`
- Python tests: `test_active.py`, `test_investigate.py`, `test_lint.py`, `test_remediate.py`, `test_sarif.py` (5 test files)
- Uses pytest (implied by test patterns)
- Coverage infrastructure present (`.coverage` in repo root suggests prior runs)

## 7. Configuration & Build

- **Build system**: maturin (PEP 517) building Rust extension
- **Packaging**: PyPI package `pyapicheck` v0.8.1
- **Entry point**: `pyapicheck = "pyapicheck.cli:main"`
- **Optional deps**: active testing extras
- **Rust editions**: Modern Rust (Cargo.toml files present)

## 8. Security Considerations

### Positive
- Focus on authorization/business logic gaps
- Evidence-based findings (reduces false alarm fatigue)
- Cedar policy generation with validation
- Traceable findings support audit trails

### Observations
- Log parsing for traffic reconciliation - needs careful handling of PII in logs
- Graph modeling of agents/MCP - sensitive topology information
- Policy artifacts need validation before deployment (explicitly warned)
- Sensitive field classification is heuristic-based

## 9. Recommendations (Audit Only - No Changes)

1. **Documentation**: Consider architecture diagrams for graph/baseline/policy flows
2. **Testing**: Expand Python integration tests for end-to-end CLI flows
3. **Error handling**: Ensure consistent error surfacing across Rust/Python boundary
4. **Observability**: Add structured logging for debugging complex flows
5. **Validation**: Strengthen schema validation for configs (MCP, Cedar)

## 10. Summary

PyAPICheck is a well-architected, traceability-focused API security analysis tool with a sophisticated Rust core. Its strength is producing explainable findings with concrete evidence rather than opaque scores. The hybrid architecture is appropriate for performance-critical parsing/scoring while keeping UX flexible in Python. It's advisory-first by design with clear boundaries about what it does/doesn't do.

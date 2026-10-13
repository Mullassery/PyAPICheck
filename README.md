# PyAPICheck

Every API risk score traces back to a named, checkable reason—never a black-box number.

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## What it is

PyAPICheck analyzes OpenAPI specifications and cross-references them with real gateway traffic to detect API security issues with full traceability. Unlike generic vulnerability scanners that return opaque severity scores, PyAPICheck produces concrete findings that cite the exact factors causing each risk, enabling teams to verify and act on them with confidence.

Built with a Rust core and Python bindings (via PyO3), PyAPICheck focuses on business-logic authorization gaps—like endpoints that should require authentication but don't, missing security schemes, or inconsistent authorization across operations. It also supports security graph modeling for AI agents/MCP tools, behavioral baselining, and Cedar policy generation.

## Features / Highlights

- **Evidence-backed findings**: Every risk factor includes a named severity and description explaining exactly why the finding exists.
- **Spec discovery**: Scan single OpenAPI specs, entire directories/monorepos, or Postman collections to inventory API surface.
- **Drift detection**: Compare spec revisions to catch newly added, removed, or changed endpoints before they ship.
- **Observed vs. declared analysis**: Cross-reference specs with access logs to identify zombie (declared but unused) and shadow (observed but undeclared) endpoints.
- **MCP/agent security graph**: Build a graph of agents, tools, and resources from live MCP configurations to analyze reachability and blast radius.
- **Behavioral baselining**: Detect BOLA-shaped access patterns and first-time operations per identity based on real traffic.
- **Cedar policy generation**: Recommend, validate, and diff Cedar authorization policies with findings backed by concrete evidence.
- **Automated remediation**: Generate machine-readable remediation plans for OpenAPI specs.
- **Traceable by design**: All findings maintain full provenance back to the specific spec locations and traffic evidence that produced them.

## Who it's for / Use cases

- **Security reviews**: Evaluate OpenAPI specs before shipping, whether for a single service or across an entire monorepo.
- **CI/CD gating**: Fail builds on high/critical findings or on API security regressions detected via spec diffing.
- **API lifecycle management**: Identify unused ("zombie") endpoints or undocumented ("shadow") endpoints by reconciling with production traffic.
- **AI agent governance**: Model MCP servers and agents to understand what they can reach, assess blast radius if compromised, and generate enforceable Cedar policies.
- **Authorization hardening**: Catch missing authentication, inconsistent security requirements, and overly permissive endpoint exposure.

## What it is not

- **Not a generic web vulnerability scanner**: PyAPICheck focuses on authorization and API surface correctness, not broad classes like XSS, SQLi, or server misconfiguration exploits. Tools like ZAP and pyapicheck are complementary.
- **Not a live enforcement engine**: It generates Cedar policies and an Envoy configuration artifact, but does not wire or deploy them to gateways. Deployment remains a manual step.
- **Not production-hardened as an enforcement control plane yet**: The system is advisory/artifact-oriented for many workflows (see Project status).
- **Not LLM-powered out of the box**: Sensitive field classification uses a lightweight keyword heuristic (designed to be swappable for models like Presidio); the AI Security Analyst (Phase 5) is not implemented at this time.

## Project status

- **Core functionality (Phases 0-4, 6-7):** Discovery, diffing, traffic reconciliation, graph modeling, behavioral baselining, Cedar policy operations, and Envoy artifact emission are implemented and covered by tests.
- **AI Security Analyst (Phase 5):** Not started. This is explicitly deferred pending citation-verifiable findings.
- **Maturity**: Advisory-first. Artifacts are designed to be validated and reviewed by humans before deployment. Envoy configs should be validated in a staging environment before production use.

## Installation

PyAPICheck is distributed as a Python package via PyPI and includes Rust-compiled extensions. Requires Python ≥ 3.9.

```bash
pip install pyapicheck
```

From source (development):

```bash
maturin develop
```

## Quick start

Analyze an OpenAPI spec and view risk findings with traceable reasons:

```bash
pyapicheck discover openapi.yaml
```

Output includes each endpoint, risk level and score, the exact risk factors (each with severity), and any sensitive fields identified (with location: query/path/body/header).

## Usage

- **Discover API surface** (single file or entire repo):
  ```bash
  pyapicheck discover openapi.yaml
  pyapicheck discover ./services/
  ```

- **Gate on regressions in CI**:
  ```bash
  pyapicheck discover openapi.yaml --fail-on-high
  ```

- **Detect drift between revisions**:
  ```bash
  pyapicheck diff old.yaml new.yaml
  ```

- **Cross-reference with access logs (zombie/shadow detection)**:
  ```bash
  pyapicheck report openapi.yaml access.log
  ```

- **Build/inspect agent security graph from MCP config**:
  ```bash
  pyapicheck graph load-mcp mcp.json
  pyapicheck graph reachable --agent <agent_id>
  pyapicheck graph blast-radius --agent <agent_id>
  ```

- **Behavioral baselining and Cedar policies**:
  ```bash
  pyapicheck baseline openapi.yaml access.log --out baseline.json
  pyapicheck policies recommend baseline.json --out policy.cedar
  pyapicheck policies validate policy.cedar
  pyapicheck policies emit-envoy policy.cedar --out envoy.yaml
  ```

- **Generate remediation plan**:
  ```bash
  pyapicheck remediate openapi.yaml --out plan.json
  ```

For all subcommands and flags, run:

```bash
pyapicheck --help
```

## Documentation

- [CHANGELOG.md](CHANGELOG.md) — Version history and release notes.
- [CONTRIBUTING.md](CONTRIBUTING.md) — Development setup, testing, and contribution guidelines.
- [ROADMAP.md](ROADMAP.md) — Phase-by-phase plan and what's done vs. deferred.
- [ROADMAP_HONEST.md](ROADMAP_HONEST.md) — Honest assessment of maturity, gaps, and technical debt.
- [SECURITY.md](SECURITY.md) — Vulnerability reporting.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes. CI runs Rust tests/clippy/fmt, builds the Python extension via maturin, runs the Python test suite, and performs a `cargo audit` dependency vulnerability check.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

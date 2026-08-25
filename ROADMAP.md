# Roadmap

This is the engineering roadmap for this repo specifically — grounded in
what's actually built, not the abstract phase list in the product strategy
doc. Each phase has a single demo-able capability as its exit criterion;
don't start the next phase until the current one's demo works on a real
(not synthetic) spec/traffic sample.

Product principles this roadmap answers to (from the vision doc): evidence
over black-box scores, the graph is ground truth, visibility before
enforcement, self-hosted first, OSS is the trust layer not a funnel.

---

## Phase 0 — OSS discovery core ✅ done (`v0.1.0`, this commit)

- OpenAPI 3.x parsing (`core/src/openapi.rs`): paths, methods, security
  (operation + global), `$ref` resolution with a cycle guard.
- Keyword-based sensitive-field classifier (`core/src/classify.rs`):
  pii / financial / credential / health.
- Transparent risk engine (`core/src/risk.rs`): every score traces to a
  named factor with a severity and a human-readable reason.
- PyO3 bindings + `pyapicheck` CLI (`discover`, `--json`, `--fail-on-high`).
- 14 Rust tests (unit + integration against a fixture with intentionally
  planted findings).

**Demo:** `pyapicheck discover <spec>` finds real, explainable issues in
under a second, self-hosted, zero infrastructure required.

---

## Phase 1 — Broaden discovery, still spec-only

Goal: don't need runtime traffic yet, but stop depending on a single
hand-picked spec file.

- [ ] Discover specs automatically from a directory / Git repo (walk for
      `openapi.y*ml`, `swagger.json`, common paths like `/docs`, `/api-docs`).
- [ ] Postman collection import as a second discovery source, normalized
      into the same `EndpointDraft` shape as the OpenAPI parser.
- [ ] OpenAPI drift detection: diff two spec snapshots (e.g. two Git
      revisions) and report added/removed/changed endpoints and fields —
      this is the first real "behavior changed" signal, still fully static.
- [ ] Pluggable classifier trait in `core` so the keyword classifier can be
      swapped or augmented (e.g. a Python-side Presidio call) without
      changing callers.
- [ ] `pyapicheck discover <directory>` — point at a repo, not a single file.

**Demo:** point `pyapicheck` at a real Git repo with multiple services and
get one unified inventory, plus a drift report between two commits.

**Explicitly deferred:** anything requiring live traffic — that's Phase 2.

---

## Phase 2 — Runtime telemetry and observed-vs-declared

Goal: know what's *actually* being called, not just what's declared.

- [ ] Inventory persistence in PostgreSQL (replace in-memory JSON as the
      source of truth; `pyapicheck` CLI becomes a thin client over it).
- [ ] Ingest one traffic source first — gateway access logs (NGINX/Envoy
      JSON log format) — before attempting OpenTelemetry or eBPF.
  Reasoning: logs are the lowest-effort source most orgs already have; OTel and eBPF are richer but add deployment complexity that isn't justified until the observed-vs-declared comparison itself is proven valuable.
- [ ] Observed-vs-declared classification: shadow (observed, not in any
      spec), zombie (in spec, zero traffic for N days), drifted (response
      shape differs from declared schema).
- [ ] `pyapicheck report` gains a traffic-volume column and lifecycle
      status (active/deprecated/zombie/shadow) per endpoint.

**Demo:** against a real service with gateway logs, correctly flag at
least one shadow endpoint and one zombie endpoint that the team didn't
know about.

**Explicitly deferred:** ClickHouse, Kafka, full cloud-gateway integration
matrix — not justified until traffic volume actually requires it (per the
strategy doc's storage architecture section).

---

## Phase 3 — Security graph + agent/MCP discovery

Goal: this is the pivot point — from "API posture tool" toward the actual
product thesis (agent/API authorization control plane).

- [ ] Graph schema in Postgres (+ AGE extension) per the vision doc: User,
      Agent, Tool/MCP server, Endpoint, Resource, Role.
- [ ] MCP server discovery: enumerate registered MCP servers and the tools
      they expose, same discovery discipline as API discovery.
- [ ] Agent identity as a first-class record, distinct from human users
      and static service accounts (owner, allowed tools/APIs, declared
      scope) — this is the non-negotiable design constraint from the
      product vision, not an implementation detail to defer.
- [ ] Graph queries answering: "what can this agent reach" and "what's the
      blast radius if this credential leaks" (multi-hop traversal).

**Demo:** for a real agent with MCP tool access, produce the reachability
graph and answer a blast-radius question a human couldn't easily answer
by reading config files.

**Explicitly deferred:** Neo4j/Memgraph migration — Postgres+AGE until
graph size or query latency actually demands it.

---

## Phase 4 — Behavioral baselining

Goal: know what's normal, per identity — human and non-human separately.

- [ ] Per-identity baseline: call frequency, resource set touched,
      sequence patterns, error rates — built from Phase 2's traffic store.
- [ ] Agent baselines specifically: agents baseline differently than
      humans (machine-regular timing, no idle periods) — do not reuse the
      human-traffic anomaly model unmodified.
- [ ] BOLA-shaped detection: resource-ID co-occurrence and sequential-ID
      traversal, cross-referenced against the ownership graph from Phase 3.
- [ ] First-time-observed-operation detection per identity (the trigger
      condition for the worked scenario in the product vision doc).

**Demo:** the exact `finance-agent` scenario from the vision doc — a
first-time-observed operation from a known agent identity, flagged
correctly, on real (or realistically synthetic) traffic.

---

## Phase 5 — AI Security Analyst

Goal: the actual differentiator. Do not start this before Phase 3/4 exist
— the analyst has nothing to reason over without the graph and baseline.

- [ ] Tool-use agent architecture: the analyst calls the platform's own
      APIs (spec, traffic, baseline, graph, classification) as literal
      tool invocations — no free-text speculation path in the design.
- [ ] Mandatory citation: every claim in a finding links to the tool-call
      result it came from; findings without a traceable citation don't ship.
- [ ] Confidence + counter-evidence field ("what would change this
      conclusion") on every finding.
- [ ] `pyapicheck investigate <path-or-agent>` CLI command.

**Demo:** a real finding, on real data, that a security engineer verifies
correct by clicking through the citations in under a minute — not a demo
script with a scripted right answer.

**Hard gate:** if findings can't be verified this way, do not proceed to
Phase 6. An unverifiable AI finding is worse than no finding (kills trust,
per the risk register in the strategy doc).

---

## Phase 6 — Agent/MCP policy (advisory)

- [ ] Cedar policy integration for agent authorization rules (allow / deny
      / require_approval), matching the YAML shape in the vision doc.
- [ ] Policy recommendations generated from Phase 4/5 findings — advisory
      output only, a human applies it. No inline enforcement yet.
- [ ] `pyapicheck policies` CLI command (list, validate, diff against
      observed agent behavior).

**Demo:** a policy-drift finding (like the vision doc's worked scenario)
that produces a concrete, applicable Cedar policy fix.

---

## Phase 7 — Enforcement integrations

- [ ] Emit gateway-consumable policy artifacts (start with one target —
      Envoy or Kong, not both) rather than sitting inline on the request
      path.
- [ ] Only start this phase once Phase 5/6 have held up against real
      adversarial or at least real production use, not just design-partner
      demos — enforcement mistakes are expensive to earn back trust from.

---

## Differentiator gap (external critique, verified) — Done

The tool is local-first by construction already (no network-client
dependency anywhere in the Rust core or Python CLI — `core/Cargo.toml`
only pulls in `serde`/`serde_json`/`serde_yaml`), so "not genuinely
offline" doesn't apply. This left one real gap: no automated remediation —
`risk.rs` only scored/explained findings, and the closest roadmap item
(Phase 6, Cedar policy recommendations) is explicitly advisory-only, "a
human applies it," and scoped to agent/MCP auth policy, not to fixing the
underlying OpenAPI spec or auth config.

**Implemented:** `pyapicheck remediate <spec>` (`core/src/remediate.rs`,
`core/src/text_patch.rs`). It closes the gap for the subset of findings
that have one safe, mechanical, unambiguous fix:
- `no_auth`: adds a `security` requirement to the operation, but only
  referencing a scheme the spec *already declares* in
  `components.securitySchemes` — it never invents an auth mechanism, only
  wires up one the API author already set up and forgot to apply on that
  operation.
- `missing_metadata`: adds a deterministic `operationId` derived from the
  method + path.

Findings with no safe automatic fix (`sensitive_data`,
`unauthenticated_sensitive_data`, `deprecated_still_live`) remain
advisory-only by design — deciding what a sensitive field *should* do, or
whether a deprecated endpoint can be removed, is a business decision this
tool has no basis to make. `--apply` writes the fix to disk; without it,
`remediate` only prints the unified diff. The patch is applied as a
targeted, format-preserving text edit (not a full parse-and-re-serialize
round trip), so the diff is minimal and existing comments/key order/quote
style in the spec are untouched.

## What's explicitly not on this roadmap

Matches the vision doc's non-goals: no general BOLA/posture scanner as a
headline feature, no inline WAF/gateway replacement, no credential/secret
lifecycle management (complementary vendors own that), no competing with
the MCP protocol itself. If a phase starts drifting toward "just add
traffic-shape anomaly detection to close a deal," that's a signal to
revisit positioning, not a reason to skip ahead on this list.

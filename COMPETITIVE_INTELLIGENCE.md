# Competitive intelligence in roadmap and upgrade work

**Policy date:** 2026-10-19

Competitive findings are an input to product decisions, not a one-off report.
Every pending roadmap item, new feature, and routine dependency upgrade should
check the repository's [`AUDIT_FINDINGS.md`](AUDIT_FINDINGS.md) before work
starts, and record the decision in the PR or changelog.

## Required check before building

1. **Read `AUDIT_FINDINGS.md`.** Find the relevant competitor row and the
   ranked next actions. If the finding is stale, update it with a dated source.
2. **Name the competitor and the user problem.** A feature is not justified by
   "competitor has it". State the workflow it unlocks, who needs it, and how
   often. Mark unverified demand as a hypothesis.
3. **Prefer reuse over new code.** Check whether an existing Mullassery repo
   already provides the capability (see `BUNDLES.md` in the profile repo and
   the bundle role file in this repo, when present). Typical reuse:
   - crawling/fetching/robots/SSRF → **MudFish**
   - architecture maps / PR diffs → **CodeAtlas**
   - data-quality contracts / validation → **StatGuardian**
   - token counting / cost tables → **PyTokenCalc**
   - dependency graph / advisories / SBOM → **PyDeepMesh**
   - segmentation / CLV / churn → **ClusterAudienceKit**
   - activation / lineage / PII → **PyReverseETL**
   - fleet state sync → **SyncFleet** (only after conflict resolution)
4. **Choose one disposition:** build, integrate, defer, or reject. Write it
   down. A rejection with a reason is a successful outcome.
5. **For routine upgrades**, check whether the upgrade closes a known
   competitor gap or breaks a differentiated capability. Run the tests that
   cover the affected path; do not merge a green build that silently changes a
   user-visible contract.

## PR / changelog checklist

- [ ] Competitor and source URL/date recorded (or "no direct competitor").
- [ ] User impact and frequency stated; unverified demand labelled.
- [ ] Reuse check done against sibling repos/bundles.
- [ ] Failure mode and rollback considered (especially auth, PII, cost).
- [ ] Docs/roadmap status updated honestly.
- [ ] Tests or a manual verification command included.

## Review cadence

- Refresh the competitor row when a release changes the capability.
- Re-check the full `AUDIT_FINDINGS.md` at least quarterly and before a major
  release.
- If a finding is wrong or stale, correct it in the same PR that relies on it.

## Non-goals

- Copying features for parity.
- Adding a dependency just because a competitor uses it.
- Treating star counts or download counts as proof of user need.

## OSS gap analysis — 2026-10-24

**What matters most here:** live capture and a gate-worthy spec diff. Export-only NDJSON and a shallow diff keep it an offline analyzer; add gateway or mirror capture and oasdiff-class breaking-change detection before claiming API risk scoring in CI.

Scope: PyAPICheck assessed against four maintained API-security/testing tools on OpenAPI/Postman discovery, evidence quality, spec drift, observed-vs-declared traffic analysis, active testing, agent/MCP modeling, policy output, and CI integration. DAST exploit breadth and gateway enforcement were assessed only to define scope boundaries.

### Comparable OSS projects

| Project | GitHub | License | Last activity | Why it is the comparison |
| --- | --- | --- | --- | --- |
| OWASP ZAP | https://github.com/zaproxy/zaproxy | Apache-2.0 | v2.17.0, 2025-12-15; pushed 2026-10-23 | The default OSS DAST/proxy; imports OpenAPI and actively attacks endpoints, the capability users compare against "API security". |
| Schemathesis | https://github.com/schemathesis/schemathesis | MIT | v4.32.4, 2026-10-22 | Property-based and stateful testing from OpenAPI/GraphQL; PyAPICheck delegates active testing to it, so it is both comparator and dependency. |
| oasdiff | https://github.com/oasdiff/oasdiff | Apache-2.0 | v1.34.1, 2026-10-21 | The reference OpenAPI diff/breaking-change engine; direct comparison for our `diff` command. |
| mitmproxy | https://github.com/mitmproxy/mitmproxy | MIT | v12.3.0, 2026-10-22 | TLS-intercepting proxy for real traffic capture and scripting; representative of the live-traffic workflow we do not provide. |

### Capability comparison

| Capability | Ours | ZAP | Schemathesis | oasdiff | mitmproxy | Gap |
| --- | --- | --- | --- | --- | --- | --- |
| OpenAPI/Postman discovery | Yes | Partial | Partial | Partial | No | Ahead |
| Evidence-cited findings | Yes | No | No | No | No | Ahead |
| Spec drift with breaking classification | Partial | No | No | Yes | No | Medium |
| Zombie/shadow endpoint detection | Yes | No | No | No | No | Ahead |
| Behavioral baselining/BOLA patterns | Partial | No | No | No | No | Ahead |
| Active security testing | Partial | Yes | Yes | No | No | Medium |
| Authn/authz contract analysis | Yes | Partial | No | No | No | Ahead |
| MCP/agent security graph | Yes | No | No | No | No | Ahead |
| Cedar policy generation | Yes | No | No | No | No | Ahead |
| Live traffic capture/proxy | No | Yes | No | No | Yes | Large |
| OpenAPI lint integration | Yes | Partial | No | No | No | Ahead |
| SARIF/CI gating | Yes | Yes | Yes | Yes | No | None |
| Runtime enforcement/blocking | No | Partial | No | No | Partial | Large |
| Platform wheel coverage | Partial | Yes | Yes | Yes | Yes | Medium |

Nuance: our traffic ingestion reads newline-delimited JSON access logs with NGINX/Envoy field aliases, method/path/status/identity only; there is no PCAP, live tap, or response body, so response-shape drift is structurally impossible. Our `diff` compares endpoint presence plus `authenticated`, `auth_schemes`, `deprecated`, and sensitive-field signatures, not request/response schemas, parameters, enums, or status codes. oasdiff covers hundreds of change kinds with breaking-change classification. Our active testing shells out to Schemathesis; we do not generate tests ourselves. ZAP's and mitmproxy's "Partial" enforcement reflects their proxy position, not gateway policy deployment. APIClarity, the closest shadow/zombie comparator, is archived and is therefore excluded from the active set.

### Gaps that matter (ranked)

1. **No live traffic capture or gateway connectors** — observed-vs-declared and behavioral baselining only work when someone exports NDJSON access logs. Envoy, Kong, AWS API Gateway, and cloud flow logs all require bespoke plumbing; mitmproxy/ZAP show users expect capture to be part of the tool. This blocks the highest-value lifecycle workflow. L effort.
2. **Spec diff is too shallow to gate on** — we detect endpoint add/remove and four auth/deprecation fields, while oasdiff classifies schema, parameter, enum, status-code, and breaking changes. A PR that adds a required field or removes a security scheme can pass our `diff` unnoticed. M effort; an oasdiff adapter is the fast path.
3. **Active testing is delegated, not differentiated** — Schemathesis is excellent, but our adapter contributes no authz-specific tests, no per-record ownership checks, and no BOLA test generation. Users still need Schemathesis or ZAP to confirm exploitability. M/L effort to add ownership-aware checks.
4. **Distribution is single-platform** — PyPI 0.8.1 ships only a macOS arm64 wheel plus sdist, despite Ubuntu CI; Linux containers and Windows users must build Rust. That is a hard blocker for CI adoption. S/M effort.
5. **Sensitive-data classification is a keyword heuristic** — risk scores for unauthenticated sensitive endpoints depend on field-name matching; false negatives understate critical findings, false positives erode trust. Presidio or a pluggable classifier is S/M effort.
6. **No GraphQL/gRPC contract coverage** — OpenAPI and Postman only; ZAP and Schemathesis cover GraphQL, and gRPC APIs are invisible. M effort if the target market includes non-REST APIs.

### Where we are differentiated

- Every finding cites a named risk factor and its spec location, and SARIF emits one result per factor rather than an opaque endpoint score.
- Observed-vs-declared reconciliation, behavioral baselining, MCP/agent reachability, and Cedar policy generation are combined in one CLI; no active OSS comparator covers that chain.
- The agent/MCP graph with blast-radius traversal addresses a 2025-2026 governance problem that ZAP, Schemathesis, oasdiff, and mitmproxy do not model.
- We compose vacuum/Spectral and Schemathesis explicitly and report missing binaries instead of pretending a skipped run passed.

### Disposition

- **Build:** gateway/Envoy traffic connectors, schema-aware diff (or an oasdiff adapter), ownership-aware authorization tests, pluggable PII classification, and Linux/Windows wheels.
- **Integrate/reuse:** keep Schemathesis for active testing and vacuum/Spectral for linting; use oasdiff for breaking-change classification rather than reimplementing it; reuse PyBlastRadius graph traversal concepts for agent blast radius.
- **Defer/reject:** DAST parity with ZAP, a live enforcement proxy, gateway policy deployment, the LLM security analyst, and GraphQL/gRPC until the REST authorization workflow is validated.

### Sources

- https://github.com/zaproxy/zaproxy and https://www.zaproxy.org/docs/desktop/addons/openapi-support/ (accessed 2026-10-24)
- https://github.com/schemathesis/schemathesis (accessed 2026-10-24)
- https://github.com/oasdiff/oasdiff and https://www.oasdiff.com/docs/breaking-changes (accessed 2026-10-24)
- https://github.com/mitmproxy/mitmproxy (accessed 2026-10-24)
- https://github.com/openclarity/apiclarity (archived; accessed 2026-10-24)
- Repo files inspected: `README.md`, `COMPETITIVE_INTELLIGENCE.md`, `AUDIT_FINDINGS.md`, `ROADMAP_HONEST.md`, `pyproject.toml`, `Cargo.toml`, `core/src/traffic.rs`, `core/src/drift.rs`, `core/src/risk.rs`, `python/pyapicheck/cli.py`

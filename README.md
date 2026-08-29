# pyapicheck

**Every risk score traces back to a named, checkable reason. Never a black-box number.**

[![PyPI](https://img.shields.io/pypi/v/pyapicheck?color=blue)](https://pypi.org/project/pyapicheck/)
[![CI](https://github.com/Mullassery/PyAPICheck/actions/workflows/ci.yml/badge.svg)](https://github.com/Mullassery/PyAPICheck/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/pyapicheck)](https://pypi.org/project/pyapicheck/)
[![License: free-to-use](https://img.shields.io/badge/license-free--to--use-lightgrey)](LICENSE)

## The problem

OpenAPI specs outgrow the point where anyone can eyeball them for security
issues. A refunds endpoint ships with no auth override. A `DELETE` route
inherits no security scheme because the global default got excluded from a
build config. A field named `account_number` sails past unnoticed. These
aren't exotic bugs — each one is a single missing YAML line, sitting
undetected in a spec with hundreds of endpoints until someone finds it the
hard way.

The tooling that exists doesn't close the gap:

- **Scanners hand you a severity number with no way to check it.** A human
  still has to go verify the finding is real before anyone acts on it —
  which means findings that can't be trusted get ignored, which defeats the
  point of scanning at all.
- **Spec-only tools don't know what's actually happening in production.**
  They can't tell a genuinely dead endpoint from a live one, or a normal
  integration calling a new resource ID from an enumeration attack.
- **Nothing is built for the problem that's arriving next**: AI agents
  calling these same APIs under their own identity, with their own
  behavioral patterns, and no authorization model designed for them.

`pyapicheck` is built around one rule: **every finding names the exact
factor that produced it.** Not "risk score: 73" — `[CRITICAL] Sensitive
data is reachable without authentication`, every time. And it doesn't stop
at the spec: it cross-references real gateway traffic, builds a security
graph of agents and what they can reach, baselines behavior per identity,
and turns findings into real [Cedar](https://www.cedarpolicy.com/) policy
you can validate and evaluate — not a report you have to take on faith.

## Table of contents

- [Install](#install)
- [Quick start](#use)
- [Discovering a whole repo, or a Postman collection](#discovering-a-whole-repo-or-a-postman-collection)
- [Drift detection](#drift-detection)
- [Observed vs. declared: shadow and zombie endpoints](#observed-vs-declared-shadow-and-zombie-endpoints)
- [Persisting to Postgres](#persisting-to-postgres-optional)
- [Automated remediation](#automated-remediation)
- [Security graph: MCP/agent discovery, reachability, blast radius](#security-graph-mcpagent-discovery-reachability-blast-radius)
- [Behavioral baselining: BOLA-shaped access and first-time operations](#behavioral-baselining-bola-shaped-access-and-first-time-operations)
- [Cedar policy: recommendations and drift detection](#cedar-policy-recommendations-and-drift-detection)
- [Emitting an enforcement artifact (Envoy)](#emitting-an-enforcement-artifact-envoy)
- [What this is (and isn't) — yet](#what-this-is-and-isnt--yet)

The parsing, classification, scoring, graph, and policy engine is Rust
(`core/`); this package is a thin Python CLI/SDK wrapper over it
(`bindings/` + `python/`), built with [PyO3](https://pyo3.rs) and
[maturin](https://www.maturin.rs).

## Install

```bash
pip install pyapicheck
```

Or from source (for Rust-side development):

```bash
uv venv .venv --python 3.12
source .venv/bin/activate
uv pip install maturin
maturin develop --release
```

## Use

```bash
pyapicheck discover examples/sample-openapi.yaml
```

```
Commerce API (1.3.0)
source: examples/sample-openapi.yaml

7 endpoints discovered  |  2 high/critical  |  2 unauthenticated  |  4 touch sensitive data

POST    /api/v1/refunds              CRITICAL           score=90
    - [HIGH] No authentication scheme declared for POST /api/v1/refunds
    - [HIGH] Endpoint handles fields classified as: financial
    - [CRITICAL] Sensitive data is reachable without authentication
    fields: account_number (financial, request)

DELETE  /api/v1/users/{id}           HIGH               score=40
    - [HIGH] No authentication scheme declared for DELETE /api/v1/users/{id}
...
```

Every finding lists *why* — that's the point. A security engineer should
never have to trust a score they can't check.

### As a library

```python
import pyapicheck

inventory = pyapicheck.discover("openapi.yaml")
for endpoint in inventory["endpoints"]:
    if endpoint["risk"]["level"] in ("HIGH", "CRITICAL"):
        print(endpoint["method"], endpoint["path"], endpoint["risk"]["factors"])
```

### Discovering a whole repo, or a Postman collection

`discover` isn't limited to one hand-picked OpenAPI file:

```bash
pyapicheck discover ./services/          # walks the tree, discovers every openapi/swagger file it finds
pyapicheck discover collection.json      # Postman Collection v2.1 export — same risk-scored report
```

A directory with multiple services prints one report per spec plus an
aggregate total; a Postman collection is auto-detected by shape (no flag
needed) and normalized into the same report format as an OpenAPI spec —
sensitive fields are classified from the collection's example request
bodies/query params instead of a schema, since Postman collections don't
carry one.

### Drift detection

```bash
pyapicheck diff old-openapi.yaml new-openapi.yaml
```

Reports endpoints added, removed, or changed (authentication, deprecation,
or sensitive-field differences) between two spec snapshots — e.g. two Git
revisions checked out to disk. This is the first "behavior changed" signal,
still fully static (no traffic required).

### Observed vs. declared: shadow and zombie endpoints

```bash
pyapicheck report openapi.yaml access.log
```

Cross-references the declared spec against a gateway access log (NDJSON,
NGINX- or Envoy-shaped JSON log lines) and flags **zombie** endpoints
(declared, zero observed requests) and **shadow** endpoints (observed
traffic hitting something not in the spec at all) — the first "what's
actually happening" signal, on top of the purely-declared risk report.

### Persisting to Postgres (optional)

By default `pyapicheck` is entirely file-in, report-out — no database
required. Add `--db-url` to `discover` or `report` to also persist the
result (each run creates a new history row rather than overwriting the
last one):

```bash
pyapicheck report openapi.yaml access.log --db-url postgres://user:pass@host/db
```

```python
import pyapicheck
inventory_id = pyapicheck.persist("postgres://user:pass@host/db", "openapi.yaml")
inventory = pyapicheck.load_inventory("postgres://user:pass@host/db", inventory_id)
```

### In CI

```bash
pyapicheck discover openapi.yaml --fail-on-high   # exit 2 if anything is HIGH/CRITICAL
pyapicheck discover openapi.yaml --json           # machine-readable output
```

### Automated remediation

For the subset of findings that have one safe, mechanical fix, `remediate`
generates (and can apply) a real patch to the spec — not just a report:

```bash
pyapicheck remediate openapi.yaml            # dry run: prints a diff, changes nothing
pyapicheck remediate openapi.yaml --apply    # writes the fix back to the file
```

```
2 fixable finding(s):

  [no_auth] POST    /api/v1/refunds              Add `security: [{bearerAuth: []}]` to POST /api/v1/refunds (references the already-declared 'bearerAuth' scheme)
  [no_auth] DELETE  /api/v1/users/{id}           Add `security: [{bearerAuth: []}]` to DELETE /api/v1/users/{id} (references the already-declared 'bearerAuth' scheme)

--- a/openapi.yaml
+++ b/openapi.yaml
@@ -108,7 +108,7 @@
       # BUG: no security override here, and the top-level default is
       # accidentally excluded from this build's deploy config — this endpoint
       # ships with no auth in production despite handling financial data.
-      security: []
+      security: [{bearerAuth: []}]
       operationId: createRefund
```

Two findings are fixable today:
- `no_auth` — adds a `security` requirement, but only referencing a scheme
  the spec *already declares* in `components.securitySchemes`. It never
  invents an auth mechanism, only wires up one the API author set up and
  forgot to apply on that operation.
- `missing_metadata` — adds a deterministic `operationId` derived from the
  method + path.

`sensitive_data`, `unauthenticated_sensitive_data`, and
`deprecated_still_live` stay advisory-only by design — deciding what a
sensitive field *should* do, or whether a deprecated endpoint can be
removed, is a business decision this tool has no basis to make for you.
The patch is a targeted, format-preserving text edit, not a full
parse-and-re-serialize round trip — comments, key order, and quote style
elsewhere in the file are untouched, so the diff stays minimal and
reviewable.

### Security graph: MCP/agent discovery, reachability, blast radius

Beyond individual API specs, `pyapicheck` can build a security graph
(Postgres + [Apache AGE](https://age.apache.org/)) of `User`/`Agent`/
`Tool`/`Endpoint`/`Resource`/`Role` nodes and answer graph questions a
config file can't answer directly:

```bash
# Discover MCP servers from a config file, live-introspect each one's real
# tool list over stdio JSON-RPC, and write them into the graph as Tool nodes.
pyapicheck graph load-mcp claude_desktop_config.json --db-url postgres://user:pass@host/db

# Declare an agent's identity and what it's allowed to call.
pyapicheck graph add-agent finance-agent --owner alice \
  --tool refunds-api --scope "process customer refunds" \
  --db-url postgres://user:pass@host/db

# "What can this agent reach" -- multi-hop traversal, not a config guess.
pyapicheck graph reachable finance-agent --db-url postgres://user:pass@host/db

# "What's the blast radius if this leaks" -- reverse traversal.
pyapicheck graph blast-radius accounts_table --db-url postgres://user:pass@host/db
```

MCP tool discovery is real, not config-trusting: each configured server is
actually spawned and asked for its tool list over the real MCP JSON-RPC
handshake (`initialize` → `tools/list`). A server that fails to start or
doesn't answer is reported `unavailable: <reason>`, never silently treated
as "zero tools." An agent can only be linked to a tool/API that's already
been discovered -- `graph add-agent` fails loudly if you reference one
that isn't in the graph yet, rather than silently no-op-ing.

### Behavioral baselining: BOLA-shaped access and first-time operations

```bash
pyapicheck baseline openapi.yaml historical-access.log current-access.log --agent finance-agent
```

Given a caller identity in the traffic (extracted from common log fields
like `user_id`/`agent_id`/`sub` -- not every gateway log carries one out of
the box), this computes per-identity baselines (request volume, error rate, distinct
resources touched, timing regularity) and two concrete, checkable
findings — not fuzzy anomaly scores:

- **Sequential-ID access** (`BOLA-shaped finding`): an identity hitting a
  single-numeric-ID endpoint with a run of near-sequential IDs (`1, 2, 3,
  4, ...`) — the classic enumeration signature.
- **First-time-observed operation**: an identity calling a declared
  endpoint it has never called before, compared against the historical
  log — the exact "a known agent does something it's never done before"
  trigger from the product vision's worked scenario. This is keyed on the
  *endpoint template*, not the concrete resource path, so touching a new
  resource ID on an already-familiar endpoint doesn't create noise.

`--agent NAME` marks an identity as a declared agent (rather than
guessing from timing); undeclared identities' timing regularity is
reported as a raw statistic, not classified as "bot" or "human" for you.

### Cedar policy: recommendations and drift detection

```bash
# Real Cedar syntax validation
pyapicheck policies validate agent-policy.cedar

# Turn Phase 4 findings into ready-to-use Cedar policy text
pyapicheck policies recommend openapi.yaml historical.log current.log --agent finance-agent

# Find findings an EXISTING policy would currently allow, with fixes
pyapicheck policies diff agent-policy.cedar openapi.yaml historical.log current.log --agent finance-agent
```

Uses [Cedar](https://www.cedarpolicy.com/) (Amazon's policy language) for
real parsing and evaluation — not a bespoke rules format. Cedar only has
two effects, `permit`/`forbid`, no native "require approval" — every
recommendation here is a `forbid`, tagged `@effect_hint("deny")` (a strong
signal, like BOLA enumeration) or `@effect_hint("require_approval")` (a
first-time operation that merits review, not an automatic verdict).

`policies diff` doesn't guess whether your existing policy covers a
finding — it actually evaluates the finding's exact (principal, action,
resource) through Cedar's real authorizer against your policy file. A
finding Cedar would currently `Allow` (e.g. a broad `permit` for an agent
with no carve-out) is a genuine gap, reported with the exact `forbid` text
that closes it.

### Emitting an enforcement artifact (Envoy)

```bash
pyapicheck policies emit-envoy agent-policy.cedar --out rbac-filter.yaml
```

Translates a Cedar policy's `forbid` rules into an Envoy
`envoy.filters.http.rbac` HTTP filter config snippet — a config artifact
for a human to splice into a real Envoy deployment's `http_filters` chain,
not something this command deploys or wires into a live request path
itself. The generated schema was verified against a real Envoy instance
(`envoyproxy/envoy`, Docker): `envoy --mode validate` accepts it, and a
live container genuinely returns `403` for the exact (principal, method,
path) a policy targets — and does not `403` a different principal or a
different endpoint for the same principal.

## What this is (and isn't) — yet

`pyapicheck` today parses **declared** API surface from an OpenAPI spec,
cross-references it against real traffic, builds a security graph of
agents/tools/resources, baselines per-identity behavior, generates/
validates Cedar policy, and can emit an Envoy enforcement artifact from
that policy. It does not yet wire that artifact into a live gateway
itself, or have an AI analyst layer — those are the next layers. See
[ROADMAP.md](ROADMAP.md) for the concrete, phase-by-phase plan from here
to the full product vision (an authorization and behavior control plane
for AI agents and the APIs/MCP servers they call). Sensitive-field
classification is a lightweight keyword heuristic
(`core/src/classify.rs`), not an NLP model — it's designed to be swapped
for something like Microsoft Presidio without changing the public API.

## Development

```bash
cargo test -p pyapicheck-core   # Rust unit + integration tests
maturin develop                 # rebuild the extension into .venv after Rust changes
```

## License

Proprietary License — Free to use with explicit attribution. See
[LICENSE](LICENSE).

---

If `pyapicheck` catches something in your API surface a scanner would've
handed you as an unexplained number, a star helps other people find it too.
Issues and PRs are welcome — see [ROADMAP.md](ROADMAP.md) for what's next
and what's deliberately not built yet.

# pyapicheck

Discover an API inventory from an OpenAPI spec, flag likely-sensitive fields,
and score every endpoint's risk — with every point on the score traced back
to a named, human-readable reason. No opaque number.

This is the free-to-use discovery core for a broader idea (a control plane for
authorizing what AI agents are allowed to do with the APIs they call) — see
the accompanying product vision doc. `pyapicheck` itself stands alone: point
it at an OpenAPI spec and it tells you, in about a second, which endpoints
are unauthenticated, which touch PII/financial/credential data, and which
combination of the two is the actual emergency.

The parsing, classification, and scoring engine is Rust (`core/`); this
package is a thin Python CLI/SDK wrapper over it (`bindings/` + `python/`),
built with [PyO3](https://pyo3.rs) and [maturin](https://www.maturin.rs).

## Install (from source, for now)

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

## What this is (and isn't) — yet

`pyapicheck` today parses **declared** API surface from an OpenAPI spec. It
does not yet do runtime traffic discovery, behavioral baselining, or agent/
MCP authorization — those are the next layers. See [ROADMAP.md](ROADMAP.md)
for the concrete, phase-by-phase plan from here to the full product vision
(an authorization and behavior control plane for AI agents and the APIs/MCP
servers they call). Sensitive-field classification is a lightweight keyword
heuristic (`core/src/classify.rs`), not an NLP model — it's designed to be
swapped for something like Microsoft Presidio without changing the public
API.

## Development

```bash
cargo test -p pyapicheck-core   # Rust unit + integration tests
maturin develop                 # rebuild the extension into .venv after Rust changes
```

## License

Proprietary License — Free to use with explicit attribution. See
[LICENSE](LICENSE).

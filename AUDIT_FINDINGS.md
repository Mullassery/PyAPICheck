# Audit findings — 2026-10-19

This file records the repository-specific findings from the portfolio audit
conducted on 2026-10-19. It is documentation only; no code or release artifacts
were changed in this pass unless explicitly noted under "Implementation status".

Sources: the repository's own README/source/workflows, GitHub metadata and
Actions runs, PyPI metadata, and official competitor documentation. Claims are
marked as verified, inferred, or open questions. "Absent" means not found in the
inspected repository/docs, not proof that it cannot exist.

## What it is

API security discovery and risk scoring from OpenAPI/Postman/traffic, with evidence-cited findings, MCP/agent graph, behavioral baselining, and Cedar policy generation.

## Verified strengths

- OpenAPI/Postman discovery; spec diff; observed-vs-declared (zombie/shadow); MCP/agent graph; behavioral baselining; Cedar recommend/validate/diff; remediation plans; provenance; 3 test files; honest phase status.
- Evidence-cited risk is a real differentiator vs black-box scores.

## Verified gaps and user-facing risks

- No live enforcement; heuristic PII classification; AI analyst not built; no SARIF/PR annotations; macOS arm64 wheel only.
- No real traffic connector demonstrated; no independent security review.

## Direct competitors

- OWASP ZAP (DAST), 42Crunch (OpenAPI audit), Salt/Noname (runtime API security), Postman/APIClarity (shadow APIs).

## Ranked next actions

- P1: SARIF + GitHub Action + live traffic connectors (Envoy/API Gateway) (L).
- P2: Presidio PII classification (S).

## Do not build

- DAST parity or a live enforcement proxy; ZAP/42Crunch/Salt own those.

## Evidence gaps / validation needed

- No production traffic; Cedar correctness beyond unit tests; no user validation.

## Recommended disposition

Invest as an evidence-first authorization auditor; avoid DAST scope.

## Implementation status

Added SARIF 2.1.0 output for `discover` (`--sarif`), so findings can be
uploaded to GitHub code scanning without a custom exporter. One result per
named risk factor; stable `pyapicheck/<factor-id>` rules. `tests/test_sarif.py`
covers shape, rule IDs, severity mapping, and empty inventories (2 passed).
PyAPICheck bumped to `0.8.0`.

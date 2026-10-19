# Queue status — 2026-10-19

This file records what was shipped, what is blocked/failed, and what is rejected for this repository. It complements `AUDIT_FINDINGS.md`.

## Shipped
- SARIF 2.1.0 output for code scanning (0.8.0).

## Blocked / failed
- Live traffic connectors and Presidio PII; Linux/Windows wheels.

## Rejected / deferred
- DAST parity or live enforcement.

## Policy

Any future feature or upgrade must check `AUDIT_FINDINGS.md` and this file before implementation. A blocked item is retried only when its external dependency is available; a rejected item needs new user evidence or a design change to reopen.

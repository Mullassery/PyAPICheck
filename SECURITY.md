# Security Policy

## Reporting a vulnerability

This is a solo-maintainer, self-hosted OSS project — there is no dedicated
security team and no SLA. Please report suspected vulnerabilities
privately rather than opening a public GitHub issue, via **GitHub's
private vulnerability reporting** on this repository (Security tab →
"Report a vulnerability"), or by opening an issue asking to be contacted
privately if that's not enabled.

Please include:
- The exact version/commit affected.
- A minimal reproduction (spec file, log line, or command) — consistent
  with this project's own stance that findings should be verifiable, a
  vulnerability report should be too.
- What you'd expect to happen vs. what actually happens.

**Response time is best-effort, not guaranteed.** This is not a funded
project with paid on-call security response.

## Supported versions

There is no formal LTS/backport policy. Only the latest release on PyPI
and the `main` branch are considered supported; older versions do not
receive backported fixes.

## Known scope notes (not vulnerabilities, but relevant to a security review)

- `pyapicheck` reads OpenAPI specs, Postman collections, and gateway
  access logs from disk/network paths you give it, and can optionally
  write to a Postgres database (`--db-url`) or spawn locally-configured
  MCP servers over stdio (`graph load-mcp`). It does not itself make
  outbound network calls beyond a user-supplied `--db-url` connection and
  user-configured MCP server subprocesses — treat any config file you
  point it at (especially an MCP server config) as something that will
  actually be executed, not just parsed.
- `pyapicheck remediate --apply` writes to the spec file on disk. Review
  the diff (`remediate` without `--apply` prints it) before applying in
  an automated pipeline.
- The Cedar policy engine (`core/src/policy.rs`) and Envoy artifact
  generation (`core/src/enforcement.rs`) produce **advisory output and
  config artifacts for a human to review** — nothing in this codebase
  applies a policy or enforcement artifact to a live system automatically.
  Treat generated Envoy/Cedar output the same as any other config you'd
  review before deploying.

See `ROADMAP_HONEST.md` for a current, honest list of known bugs and
unaddressed technical debt (including dependency risk) — some of those
may have security implications even if not formally classified as CVEs.

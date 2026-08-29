"""pyapicheck: discover an API inventory from an OpenAPI spec, with every
risk score traced back to the named factors that produced it.

    >>> import pyapicheck
    >>> inventory = pyapicheck.discover("openapi.yaml")
    >>> inventory["summary"]["high_or_critical"]
    2

The heavy lifting (parsing, classification, scoring) happens in the Rust
core (`pyapicheck._core`); this package is a thin, inspectable Python layer
on top of it plus the `pyapicheck` CLI.
"""

import json
import os
from importlib import metadata as _metadata

from . import _core


def discover(spec_path: str) -> dict:
    """Parse the OpenAPI spec at `spec_path` and return the risk-scored
    inventory as a plain dict (JSON-serializable)."""
    return json.loads(_core.discover(spec_path))


def discover_directory(directory: str) -> list:
    """Recursively find every OpenAPI/Swagger spec under `directory` and
    return one risk-scored inventory dict per spec found (possibly empty)."""
    return json.loads(_core.discover_directory(directory))


def discover_path(path: str):
    """Discover `path`, whether it's a single spec file (returns a dict) or
    a directory (returns a list of dicts, one per spec found within it)."""
    if os.path.isdir(path):
        return discover_directory(path)
    return discover(path)


def diff(old_spec_path: str, new_spec_path: str) -> dict:
    """Discover both spec files and diff the resulting inventories: which
    endpoints were added, removed, or changed (auth, deprecation, or
    sensitive-field differences) between them."""
    return json.loads(_core.diff(old_spec_path, new_spec_path))


def report(spec_path: str, access_log_path: str) -> dict:
    """Discover `spec_path` and cross-reference it against the gateway
    access log at `access_log_path` (NDJSON, NGINX- or Envoy-shaped).
    Returns `{"inventory": ..., "lifecycle": {"active": [...],
    "zombie": [...], "shadow": [...]}}`."""
    return json.loads(_core.report(spec_path, access_log_path))


def baseline(
    spec_path: str,
    historical_log_path: str,
    current_log_path: str,
    known_agents: list = None,
) -> dict:
    """Discover `spec_path`, then compute per-identity baselines (call
    frequency, error rate, timing regularity) over the combined historical
    + current traffic, BOLA-shaped sequential-ID findings over current
    traffic, and first-time-observed-operation findings (current vs.
    historical) per identity. `known_agents` marks which identities are
    declared agents (e.g. from `graph_reachable`'s Agent vertices) rather
    than inferring it from timing alone. Returns `{"baselines": [...],
    "bola_findings": [...], "first_time_operations": [...]}`."""
    return json.loads(
        _core.baseline(spec_path, historical_log_path, current_log_path, known_agents or [])
    )


def policies_validate(policy_path: str) -> list:
    """Parse and validate the Cedar policy file at `policy_path` using
    real Cedar syntax validation. Returns a list of
    `{"id", "effect", "annotations"}` on success; raises on a parse error
    (Cedar's own error message)."""
    return json.loads(_core.policies_validate(policy_path))


def policies_recommend(
    spec_path: str,
    historical_log_path: str,
    current_log_path: str,
    known_agents: list = None,
) -> list:
    """Run Phase 4's baseline detectors over `spec_path`/the two traffic
    logs and generate Cedar policy recommendations from the findings:
    BOLA-shaped findings become `effect_hint: "deny"` policies, first-time
    operations become `effect_hint: "require_approval"` policies (Cedar
    itself only has permit/forbid -- every recommendation is a `forbid`;
    see `pyapicheck.policy` module docs for why). Returns a list of
    `{"policy_text", "effect_hint", "reason"}`."""
    return json.loads(
        _core.policies_recommend(
            spec_path, historical_log_path, current_log_path, known_agents or []
        )
    )


def policies_diff(
    policy_path: str,
    spec_path: str,
    historical_log_path: str,
    current_log_path: str,
    known_agents: list = None,
) -> list:
    """Run Phase 4's baseline detectors, then check each finding against
    the existing Cedar policy file at `policy_path` using real Cedar
    evaluation. Returns policy gaps -- findings the policy would currently
    `Allow` -- each with a ready-to-add `forbid` fix. An empty list means
    every finding is already covered (or there were no findings)."""
    return json.loads(
        _core.policies_diff(
            policy_path, spec_path, historical_log_path, current_log_path, known_agents or []
        )
    )


def policies_emit_envoy(policy_path: str) -> str:
    """Parse the Cedar policy file at `policy_path` and emit an Envoy
    `envoy.filters.http.rbac` HTTP filter config snippet (YAML)
    implementing its `forbid` policies -- a gateway-consumable artifact
    for a human to review and splice into a real Envoy deployment, not
    something this function deploys itself. Returns `None` if the policy
    set has no `forbid` policies to translate."""
    return _core.policies_emit_envoy(policy_path)


def persist(database_url: str, spec_path: str, access_log_path: str = None) -> int:
    """Discover `spec_path` (and, if given, cross-reference
    `access_log_path`), then persist the result to the Postgres database at
    `database_url` (running migrations first). Returns the new inventory's
    row id. Opt-in only -- nothing else in this package touches a database
    unless this is called explicitly."""
    return _core.persist(database_url, spec_path, access_log_path)


def load_inventory(database_url: str, inventory_id: int) -> dict:
    """Re-read a previously `persist`-ed inventory back from Postgres."""
    return json.loads(_core.load_inventory(database_url, inventory_id))


def graph_load_mcp(database_url: str, config_path: str, timeout_secs: int = 10) -> list:
    """Discover MCP servers from an `mcpServers`-shaped config file
    (Claude Desktop's `claude_desktop_config.json` / a project's
    `.mcp.json`), live-introspect each one's real tool list over stdio
    JSON-RPC (best-effort, `timeout_secs` per server), and write them into
    the security graph as `Tool` vertices. Returns the discovery results."""
    return json.loads(_core.graph_load_mcp(database_url, config_path, timeout_secs))


def graph_add_agent(
    database_url: str,
    name: str,
    owner: str,
    allowed_tools: list = None,
    allowed_apis: list = None,
    declared_scope: str = "",
) -> None:
    """Write an agent identity into the security graph, linking it to its
    declared tools/APIs (which must already exist as `Tool`/`Endpoint`
    vertices, e.g. via `graph_load_mcp`)."""
    agent = {
        "name": name,
        "owner": owner,
        "allowed_tools": allowed_tools or [],
        "allowed_apis": allowed_apis or [],
        "declared_scope": declared_scope,
    }
    _core.graph_add_agent(database_url, json.dumps(agent))


def graph_reachable(database_url: str, agent_name: str) -> list:
    """"What can this agent reach": every node connected from `agent_name`
    via any path of graph edges, as a list of `{"label": ..., "name": ...}`."""
    return json.loads(_core.graph_reachable(database_url, agent_name))


def graph_blast_radius(database_url: str, resource_name: str) -> list:
    """"What's the blast radius if this resource/credential leaks": every
    Agent/User with a path into `resource_name`."""
    return json.loads(_core.graph_blast_radius(database_url, resource_name))


def remediate(spec_path: str) -> dict:
    """Compute the remediation plan for the OpenAPI spec at `spec_path`:
    a `fixes` list (each a safe, mechanical spec change) and
    `patched_spec_text` (the spec with every fix applied, in the same
    format -- YAML or JSON -- as the input). Nothing is written to disk;
    the caller decides whether to write `patched_spec_text` back."""
    return json.loads(_core.remediate(spec_path))


try:
    __version__ = _metadata.version("pyapicheck")
except _metadata.PackageNotFoundError:  # pragma: no cover - editable/dev installs
    __version__ = "0.0.0"

__all__ = [
    "discover",
    "discover_directory",
    "discover_path",
    "diff",
    "report",
    "baseline",
    "policies_validate",
    "policies_recommend",
    "policies_diff",
    "policies_emit_envoy",
    "persist",
    "load_inventory",
    "graph_load_mcp",
    "graph_add_agent",
    "graph_reachable",
    "graph_blast_radius",
    "remediate",
    "__version__",
]

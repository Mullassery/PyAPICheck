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
    "persist",
    "load_inventory",
    "remediate",
    "__version__",
]

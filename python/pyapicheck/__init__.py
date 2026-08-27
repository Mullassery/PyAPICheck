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
    "remediate",
    "__version__",
]

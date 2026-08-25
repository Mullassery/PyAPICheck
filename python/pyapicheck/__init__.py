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
from importlib import metadata as _metadata

from . import _core


def discover(spec_path: str) -> dict:
    """Parse the OpenAPI spec at `spec_path` and return the risk-scored
    inventory as a plain dict (JSON-serializable)."""
    return json.loads(_core.discover(spec_path))


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

__all__ = ["discover", "remediate", "__version__"]

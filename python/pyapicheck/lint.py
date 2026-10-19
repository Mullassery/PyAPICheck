"""Optional OpenAPI linting via vacuum/Spectral.

Schemathesis tests behavior; vacuum/Spectral lint the contract itself. This
adapter shells out to whichever MIT/Apache-2.0 CLI is installed, parses JSON
output when available, and never invents findings.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any


class LinterUnavailable(RuntimeError):
    """Raised when no supported OpenAPI linter is installed."""


@dataclass
class LintResult:
    tool: str
    exit_code: int
    findings: list[dict[str, Any]] = field(default_factory=list)
    raw: str = ""

    @property
    def passed(self) -> bool:
        return self.exit_code == 0 and not self.findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "exit_code": self.exit_code,
            "passed": self.passed,
            "findings": self.findings,
        }


def _resolve(tool: str) -> str | None:
    return shutil.which(tool)


def _parse_findings(tool: str, stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("results", "issues", "findings", "errors"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def run_lint(
    spec_path: str,
    *,
    tool: str = "auto",
    timeout: int = 120,
    extra_args: Iterable[str] | None = None,
) -> LintResult:
    """Run vacuum or Spectral against an OpenAPI spec."""
    chosen = tool
    if tool == "auto":
        if _resolve("vacuum"):
            chosen = "vacuum"
        elif _resolve("spectral"):
            chosen = "spectral"
        else:
            raise LinterUnavailable(
                "No OpenAPI linter found. Install vacuum (MIT) or Spectral "
                "(Apache-2.0), or pass tool='vacuum'/'spectral'."
            )
    binary = _resolve(chosen)
    if binary is None:
        raise LinterUnavailable(f"{chosen} was not found on PATH")

    if chosen == "vacuum":
        command = [binary, "lint", spec_path, "--json"]
    elif chosen == "spectral":
        command = [binary, "lint", spec_path, "--format", "json"]
    else:
        raise ValueError("tool must be 'auto', 'vacuum', or 'spectral'")
    command.extend(extra_args or [])

    completed = subprocess.run(
        command, capture_output=True, text=True, timeout=timeout, check=False
    )
    findings = _parse_findings(chosen, completed.stdout)
    return LintResult(
        tool=chosen,
        exit_code=completed.returncode,
        findings=findings,
        raw=completed.stdout or completed.stderr,
    )


__all__ = ["LintResult", "LinterUnavailable", "run_lint"]

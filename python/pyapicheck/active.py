"""Optional active API testing through Schemathesis.

Static discovery finds suspicious operations; Schemathesis (MIT) generates and
executes property-based/stateful tests from the same OpenAPI schema. This
adapter shells out to the installed CLI, parses its JSON report, and returns a
structured summary. It never fabricates a passing run: a missing binary or a
non-zero exit is surfaced.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class SchemathesisUnavailable(RuntimeError):
    """Raised when the Schemathesis CLI is not installed."""


@dataclass
class ActiveTestResult:
    spec: str
    base_url: str
    exit_code: int
    report: dict[str, Any]
    command: list[str] = field(default_factory=list)
    report_path: str | None = None

    @property
    def failures(self) -> list[dict[str, Any]]:
        return list(self.report.get("failures") or [])

    @property
    def errors(self) -> list[dict[str, Any]]:
        return list(self.report.get("errors") or [])

    @property
    def test_cases(self) -> dict[str, Any]:
        return dict(self.report.get("test_cases") or {})

    @property
    def passed(self) -> bool:
        return self.exit_code == 0 and not self.failures and not self.errors

    def summary(self) -> dict[str, Any]:
        operations = self.report.get("operations") or {}
        return {
            "spec": self.spec,
            "base_url": self.base_url,
            "exit_code": self.exit_code,
            "passed": self.passed,
            "operations": operations,
            "test_cases": self.test_cases,
            "failures": len(self.failures),
            "errors": len(self.errors),
            "stop_reason": self.report.get("stop_reason"),
            "running_time_seconds": self.report.get("running_time"),
        }


def _resolve_command() -> list[str]:
    binary = shutil.which("schemathesis")
    if binary:
        return [binary]
    try:
        import schemathesis  # noqa: F401
    except ImportError as exc:
        raise SchemathesisUnavailable(
            "Schemathesis is not installed. Install the MIT-licensed CLI with "
            '`pip install "pyapicheck[active]"` (or `pip install schemathesis`).'
        ) from exc
    return [sys.executable, "-m", "schemathesis"]


def run_active_tests(
    spec_path: str,
    base_url: str,
    *,
    checks: Iterable[str] | None = None,
    phases: Iterable[str] | None = None,
    max_time: int | None = None,
    max_failures: int | None = None,
    workers: int | None = None,
    headers: dict[str, str] | None = None,
    auth: str | None = None,
    extra_args: Iterable[str] | None = None,
    timeout: int = 900,
) -> ActiveTestResult:
    """Run Schemathesis against ``spec_path`` and parse its JSON report."""
    if not Path(spec_path).is_file():
        raise FileNotFoundError(f"OpenAPI spec not found: {spec_path}")
    if not base_url:
        raise ValueError("base_url is required for active testing")

    command = _resolve_command()
    with tempfile.TemporaryDirectory(prefix="pyapicheck-schemathesis-") as temp_dir:
        report_dir = Path(temp_dir)
        command = command + [
            "run",
            spec_path,
            "--url",
            base_url,
            "--report",
            "json",
            "--report-dir",
            str(report_dir),
        ]
        if checks:
            command.extend(["--checks", ",".join(checks)])
        if phases:
            command.extend(["--phases", ",".join(phases)])
        if max_time is not None:
            command.extend(["--max-time", str(max_time)])
        if max_failures is not None:
            command.extend(["--max-failures", str(max_failures)])
        if workers is not None:
            command.extend(["--workers", str(workers)])
        if auth:
            command.extend(["--auth", auth])
        for name, value in (headers or {}).items():
            command.extend(["--header", f"{name}:{value}"])
        command.extend(extra_args or [])

        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        reports = sorted(report_dir.glob("json-*.json"))
        if not reports:
            detail = (completed.stderr or completed.stdout or "").strip()
            raise RuntimeError(
                "Schemathesis produced no JSON report "
                f"(exit {completed.returncode}): {detail[:800]}"
            )
        report_path = reports[-1]
        report = json.loads(report_path.read_text(encoding="utf-8"))
        return ActiveTestResult(
            spec=spec_path,
            base_url=base_url,
            exit_code=completed.returncode,
            report=report,
            command=command,
            report_path=str(report_path),
        )


__all__ = [
    "ActiveTestResult",
    "SchemathesisUnavailable",
    "run_active_tests",
]

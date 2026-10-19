"""vacuum/Spectral adapter tests with a fake executable."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from pyapicheck.lint import LinterUnavailable, run_lint


def _fake(tmp_path: Path, name: str, payload: dict, code: int = 1) -> Path:
    script = tmp_path / name
    script.write_text(
        "#!/usr/bin/env python3\n"
        f"import sys;sys.stdout.write({json.dumps(payload)!r});sys.exit({code})\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


def test_vacuum_findings_parse(tmp_path, monkeypatch):
    _fake(tmp_path, "vacuum", {"results": [{"rule": "operation-description", "message": "missing"}]})
    spec = tmp_path / "openapi.json"
    spec.write_text("{}")
    monkeypatch.setenv("PATH", str(tmp_path) + ":" + __import__("os").environ.get("PATH", ""))
    result = run_lint(str(spec), tool="vacuum")
    assert not result.passed
    assert result.findings[0]["rule"] == "operation-description"


def test_missing_linter_is_actionable(tmp_path, monkeypatch):
    spec = tmp_path / "openapi.json"
    spec.write_text("{}")
    monkeypatch.setattr("shutil.which", lambda _: None)
    with pytest.raises(LinterUnavailable, match="OpenAPI linter"):
        run_lint(str(spec))

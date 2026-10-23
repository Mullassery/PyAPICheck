"""Schemathesis adapter tests use a fake executable/report."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from pyapicheck.active import SchemathesisUnavailable, run_active_tests


def _fake_schemathesis(tmp_path: Path, report: dict, exit_code: int = 0) -> Path:
    script = tmp_path / "schemathesis"
    payload = json.dumps(report)
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, sys\n"
        "args = sys.argv\n"
        "out = pathlib.Path(args[args.index('--report-dir') + 1])\n"
        "out.mkdir(parents=True, exist_ok=True)\n"
        f"(out / 'json-test.json').write_text({payload!r})\n"
        f"sys.exit({exit_code})\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


REPORT = {
    "stop_reason": "completed",
    "exit_code": 0,
    "running_time": 1.2,
    "operations": {"total": 2, "selected": 2, "tested": 2, "errored": 0},
    "test_cases": {"generated": 10, "with_failures": 0, "unique_failures": 0},
    "failures": [],
    "errors": [],
}


def test_active_run_parses_report(tmp_path, monkeypatch):
    _fake_schemathesis(tmp_path, REPORT)
    spec = tmp_path / "openapi.json"
    spec.write_text("{}")
    monkeypatch.setenv("PATH", str(tmp_path) + ":" + __import__("os").environ.get("PATH", ""))
    result = run_active_tests(str(spec), "http://127.0.0.1:9")
    assert result.passed
    assert result.summary()["operations"]["tested"] == 2


def test_active_run_propagates_failures(tmp_path, monkeypatch):
    report = dict(REPORT, exit_code=1, failures=[{"title": "Server Error"}])
    _fake_schemathesis(tmp_path, report, exit_code=1)
    spec = tmp_path / "openapi.json"
    spec.write_text("{}")
    monkeypatch.setenv("PATH", str(tmp_path) + ":" + __import__("os").environ.get("PATH", ""))
    result = run_active_tests(str(spec), "http://127.0.0.1:9", timeout=10)
    assert not result.passed
    assert result.failures[0]["title"] == "Server Error"


def test_missing_schemathesis_is_actionable(monkeypatch, tmp_path):
    spec = tmp_path / "openapi.json"
    spec.write_text("{}")
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr("shutil.which", lambda _: None)
    import sys

    monkeypatch.setitem(sys.modules, "schemathesis", None)
    with pytest.raises(SchemathesisUnavailable, match="pyapicheck\\[active\\]"):
        run_active_tests(str(spec), "http://127.0.0.1:9")


def test_resolves_entry_point_when_script_not_on_path(monkeypatch):
    """Regression: `python -m schemathesis` does not exist in Schemathesis 4.x.

    When the console script is absent from PATH (venv used without activation)
    but the package is importable, fall back to the console-script entry point.
    """
    pytest.importorskip("schemathesis")
    import sys

    from pyapicheck import active

    monkeypatch.setattr("shutil.which", lambda _: None)
    command = active._resolve_command()
    assert command[0] == sys.executable
    assert "schemathesis.cli" in command[-1]

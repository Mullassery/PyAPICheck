"""Python-level tests for `pyapicheck.remediate` and the `remediate` CLI
subcommand -- these require the native extension to be built and importable
(`maturin develop`), same as the Rust `discover_test.rs` suite this project
already has covers `discover`.
"""

from __future__ import annotations

import json
import os

import pytest

pyapicheck = pytest.importorskip("pyapicheck")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_SPEC = os.path.join(REPO_ROOT, "core", "tests", "fixtures", "sample-openapi.yaml")


def test_remediate_finds_the_two_unauthenticated_endpoints():
    plan = pyapicheck.remediate(SAMPLE_SPEC)

    fixes = plan["fixes"]
    no_auth = [f for f in fixes if f["factor_id"] == "no_auth"]
    assert len(no_auth) == 2
    targets = {(f["method"], f["path"]) for f in no_auth}
    assert targets == {("POST", "/api/v1/refunds"), ("DELETE", "/api/v1/users/{id}")}
    for f in no_auth:
        assert f["scheme_name"] == "bearerAuth"


def test_remediate_patched_text_is_a_minimal_diff():
    with open(SAMPLE_SPEC, "r", encoding="utf-8") as f:
        original = f.read()

    plan = pyapicheck.remediate(SAMPLE_SPEC)
    patched = plan["patched_spec_text"]

    assert patched != original
    # Comments and the rest of the document must survive untouched -- this
    # is a format-preserving text patch, not a full re-serialization.
    assert "# BUG: no security override here" in patched
    assert "# BUG: destructive operation with no auth" in patched
    original_lines = original.splitlines()
    patched_lines = patched.splitlines()
    assert len(patched_lines) == len(original_lines)
    unchanged = [
        line for line in original_lines if line.strip() != "security: []"
    ]
    for line in unchanged:
        assert line in patched_lines, f"line should be untouched: {line!r}"


def test_remediate_patched_text_reparses_as_authenticated(tmp_path):
    plan = pyapicheck.remediate(SAMPLE_SPEC)
    patched_file = tmp_path / "patched.yaml"
    patched_file.write_text(plan["patched_spec_text"], encoding="utf-8")

    inventory = pyapicheck.discover(str(patched_file))
    endpoints = {(e["method"], e["path"]): e for e in inventory["endpoints"]}

    assert endpoints[("POST", "/api/v1/refunds")]["authenticated"] is True
    assert endpoints[("DELETE", "/api/v1/users/{id}")]["authenticated"] is True


class TestRemediateCli:
    def test_dry_run_does_not_write(self, tmp_path, capsys):
        from pyapicheck.cli import main

        spec_copy = tmp_path / "spec.yaml"
        with open(SAMPLE_SPEC, "r", encoding="utf-8") as f:
            original = f.read()
        spec_copy.write_text(original, encoding="utf-8")

        exit_code = main(["remediate", str(spec_copy)])
        captured = capsys.readouterr()

        assert exit_code == 0
        assert "2 fixable finding(s)" in captured.out
        assert "Dry run" in captured.out
        assert spec_copy.read_text(encoding="utf-8") == original

    def test_apply_writes_the_patched_file(self, tmp_path, capsys):
        from pyapicheck.cli import main

        spec_copy = tmp_path / "spec.yaml"
        with open(SAMPLE_SPEC, "r", encoding="utf-8") as f:
            spec_copy.write_text(f.read(), encoding="utf-8")

        exit_code = main(["remediate", str(spec_copy), "--apply"])
        captured = capsys.readouterr()

        assert exit_code == 0
        assert "Applied 2 fix(es)" in captured.out
        patched_content = spec_copy.read_text(encoding="utf-8")
        assert "security: [{bearerAuth: []}]" in patched_content

        # Re-running discover against the now-patched file on disk confirms
        # the write was real, not just printed.
        inventory = pyapicheck.discover(str(spec_copy))
        refunds = next(
            e
            for e in inventory["endpoints"]
            if e["path"] == "/api/v1/refunds" and e["method"] == "POST"
        )
        assert refunds["authenticated"] is True

    def test_json_flag_prints_full_plan(self, tmp_path, capsys):
        from pyapicheck.cli import main

        spec_copy = tmp_path / "spec.yaml"
        with open(SAMPLE_SPEC, "r", encoding="utf-8") as f:
            spec_copy.write_text(f.read(), encoding="utf-8")

        exit_code = main(["remediate", str(spec_copy), "--json"])
        captured = capsys.readouterr()

        assert exit_code == 0
        # The JSON plan is printed as its own `json.dumps(..., indent=2)`
        # block after the human-readable summary/diff; find that block by
        # its line-initial "{" (the diff text also contains inline `{`
        # characters, e.g. `security: [{bearerAuth: []}]`, so a plain
        # rindex("{") would grab the wrong one).
        lines = captured.out.splitlines()
        json_start_line = max(i for i, line in enumerate(lines) if line == "{")
        remainder = "\n".join(lines[json_start_line:])
        plan, _ = json.JSONDecoder().raw_decode(remainder)
        assert len(plan["fixes"]) == 2

    def test_no_fixable_findings_reports_cleanly(self, tmp_path, capsys):
        from pyapicheck.cli import main

        spec = tmp_path / "clean.yaml"
        spec.write_text(
            """openapi: 3.0.3
info:
  title: t
  version: "1.0"
security:
  - bearerAuth: []
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
paths:
  /widgets:
    get:
      operationId: listWidgets
      summary: List widgets
      responses:
        "200":
          description: ok
""",
            encoding="utf-8",
        )

        exit_code = main(["remediate", str(spec)])
        captured = capsys.readouterr()

        assert exit_code == 0
        assert "No fixable findings" in captured.out

    def test_missing_file_is_a_clean_error(self, capsys):
        from pyapicheck.cli import main

        exit_code = main(["remediate", "/nonexistent/spec.yaml"])
        captured = capsys.readouterr()

        assert exit_code == 1
        assert "error:" in captured.err

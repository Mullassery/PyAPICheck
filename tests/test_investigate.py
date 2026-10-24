"""Tests for the deterministic, citation-first `investigate` command."""

import json
from pathlib import Path

import pyapicheck

FIXTURE_SPEC = str(
    Path(__file__).resolve().parents[1] / "core" / "tests" / "fixtures" / "sample-openapi.yaml"
)


def _write_log(path: Path, rows: list[dict]) -> str:
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    return str(path)


def test_investigate_attaches_citations_to_every_finding(tmp_path):
    historical = _write_log(
        tmp_path / "hist.ndjson",
        [
            {
                "request_method": "GET",
                "request_uri": "/api/v1/customers/1",
                "status": 200,
                "user_id": "agent-1",
                "timestamp": "2026-10-01T00:00:00Z",
            }
        ],
    )
    current = _write_log(
        tmp_path / "current.ndjson",
        [
            {
                "request_method": "GET",
                "request_uri": f"/api/v1/customers/{index}",
                "status": 200,
                "user_id": "agent-1",
                "timestamp": f"2026-10-02T00:00:0{index}Z",
            }
            for index in range(10, 15)
        ]
        + [
            {
                "request_method": "POST",
                "request_uri": "/api/v1/customers",
                "status": 201,
                "user_id": "agent-1",
                "timestamp": "2026-10-02T00:00:09Z",
            }
        ],
    )

    report = pyapicheck.investigate(
        FIXTURE_SPEC, historical, current, known_agents=["agent-1"]
    )

    assert report["tool_calls"]
    assert report["findings"]
    for finding in report["findings"]:
        assert 0.0 < finding["confidence"] <= 1.0
        assert finding["counter_evidence"]
        assert finding["evidence"]
        for evidence in finding["evidence"]:
            assert 0 <= evidence["citation"] < len(report["tool_calls"])

    kinds = {finding["kind"] for finding in report["findings"]}
    assert "bola_sequential_id_access" in kinds
    assert "first_time_operation" in kinds


def test_known_agent_raises_first_time_confidence(tmp_path):
    historical = _write_log(tmp_path / "hist.ndjson", [])
    current = _write_log(
        tmp_path / "current.ndjson",
        [
            {
                "request_method": "POST",
                "request_uri": "/api/v1/customers",
                "status": 201,
                "user_id": "agent-1",
                "timestamp": "2026-10-02T00:00:00Z",
            }
        ],
    )

    unknown = pyapicheck.investigate(FIXTURE_SPEC, historical, current)
    known = pyapicheck.investigate(
        FIXTURE_SPEC, historical, current, known_agents=["agent-1"]
    )

    unknown_finding = next(
        finding
        for finding in unknown["findings"]
        if finding["kind"] == "first_time_operation"
    )
    known_finding = next(
        finding
        for finding in known["findings"]
        if finding["kind"] == "first_time_operation"
    )
    assert unknown_finding["confidence"] < known_finding["confidence"]

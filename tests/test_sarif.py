"""SARIF export tests."""

from pyapicheck.sarif import build_sarif


def _inventory():
    return {
        "source": "openapi.yaml",
        "endpoints": [
            {
                "method": "POST",
                "path": "/payments",
                "risk": {
                    "score": 90,
                    "level": "CRITICAL",
                    "factors": [
                        {
                            "id": "no_auth",
                            "description": "No authentication scheme declared",
                            "weight": 40,
                            "severity": "HIGH",
                        },
                        {
                            "id": "sensitive_data",
                            "description": "Endpoint handles financial fields",
                            "weight": 30,
                            "severity": "HIGH",
                        },
                    ],
                },
            }
        ],
    }


def test_sarif_shape_rules_and_results():
    sarif = build_sarif([_inventory()], tool_version="0.8.0")
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["version"] == "0.8.0"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {
        "pyapicheck/no_auth",
        "pyapicheck/sensitive_data",
    }
    assert len(run["results"]) == 2
    first = run["results"][0]
    assert first["ruleId"] == "pyapicheck/no_auth"
    assert first["level"] == "error"
    assert "POST /payments" in first["message"]["text"]
    assert first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "openapi.yaml"


def test_sarif_empty_inventory_has_valid_empty_run():
    sarif = build_sarif([{"source": "empty.yaml", "endpoints": []}])
    run = sarif["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []

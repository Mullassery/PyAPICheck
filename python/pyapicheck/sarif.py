"""SARIF 2.1.0 output for PyAPICheck inventories.

GitHub code scanning and other SARIF consumers can ingest API risk findings
without a custom exporter. Every result keeps the same evidence as the JSON
report: one result per named risk factor, with the endpoint in the message.
"""

from __future__ import annotations

from typing import Any, Dict, List

_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def build_sarif(inventories: List[Dict[str, Any]], tool_version: str = "") -> Dict[str, Any]:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for inventory in inventories:
        source = inventory.get("source", "openapi")
        for endpoint in inventory.get("endpoints", []):
            risk = endpoint.get("risk", {})
            for factor in risk.get("factors", []):
                rule_id = "pyapicheck/" + factor.get("id", "unknown")
                rules.setdefault(
                    rule_id,
                    {
                        "id": rule_id,
                        "name": factor.get("id", "unknown"),
                        "shortDescription": {"text": factor.get("description", "")},
                        "fullDescription": {
                            "text": "PyAPICheck risk factor from an OpenAPI/Postman inventory."
                        },
                        "properties": {"severity": factor.get("severity", "UNKNOWN")},
                    },
                )
                results.append(
                    {
                        "ruleId": rule_id,
                        "level": _LEVEL.get(factor.get("severity", ""), "warning"),
                        "message": {
                            "text": "%s %s: %s"
                            % (
                                endpoint.get("method", "?"),
                                endpoint.get("path", "?"),
                                factor.get("description", ""),
                            )
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": source},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                        "properties": {
                            "endpoint": "%s %s"
                            % (endpoint.get("method", "?"), endpoint.get("path", "?")),
                            "riskScore": risk.get("score", 0),
                            "riskLevel": risk.get("level", "UNKNOWN"),
                            "factorWeight": factor.get("weight", 0),
                        },
                    }
                )

    driver: Dict[str, Any] = {
        "name": "PyAPICheck",
        "informationUri": "https://github.com/Mullassery/PyAPICheck",
        "rules": [rules[key] for key in sorted(rules)],
    }
    if tool_version:
        driver["version"] = tool_version

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }

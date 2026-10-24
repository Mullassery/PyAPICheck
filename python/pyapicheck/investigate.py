"""Deterministic, citation-first security investigator (Phase 5).

This is the non-LLM half of the roadmap's AI Security Analyst: every finding
is produced by an actual call to the platform's own APIs, and every claim
carries a citation back to the tool call and the observation that produced it.
There is no free-text speculation path and no hidden scoring.

The LLM planner that would choose which tools to call is deliberately not
wired in yet (it needs a real model/API decision, as the roadmap states). This
module runs the same tool sequence a planner would for the common
agent-authorization investigation, deterministically.
"""

from __future__ import annotations

import datetime as _dt
import json
from typing import Any

from . import _core


def _citation(
    tool_calls: list[dict[str, Any]],
    tool: str,
    arguments: dict[str, Any],
    observation: dict[str, Any],
) -> int:
    tool_calls.append(
        {"tool": tool, "arguments": arguments, "observation": observation}
    )
    return len(tool_calls) - 1


def _bola_finding(
    finding: dict[str, Any],
    tool_calls: list[dict[str, Any]],
    baseline_args: dict[str, Any],
) -> dict[str, Any]:
    citation = _citation(
        tool_calls,
        "pyapicheck.baseline",
        baseline_args,
        {
            "identity": finding["identity"],
            "method": finding["method"],
            "path_template": finding["path_template"],
            "run_length": finding["run_length"],
            "accessed_ids": finding["accessed_ids"],
        },
    )
    return {
        "id": f"bola-{finding['identity']}-{finding['method']}-{finding['path_template']}",
        "kind": "bola_sequential_id_access",
        "severity": "high",
        "confidence": 0.85,
        "title": "Sequential ID enumeration by a single identity",
        "summary": (
            f"{finding['identity']} accessed {finding['run_length']} near-sequential "
            f"IDs on {finding['method']} {finding['path_template']}."
        ),
        "evidence": [
            {
                "claim": "Sequential-ID run observed in current traffic",
                "citation": citation,
            }
        ],
        "counter_evidence": (
            "Sequential IDs can also be benign pagination, a batch job, or a "
            "retry loop. Confirm against per-record ownership data; this "
            "project has no resource-instance ownership source yet."
        ),
    }


def _first_time_finding(
    operation: dict[str, Any],
    tool_calls: list[dict[str, Any]],
    baseline_args: dict[str, Any],
) -> dict[str, Any]:
    citation = _citation(
        tool_calls,
        "pyapicheck.baseline",
        baseline_args,
        {
            "identity": operation["identity"],
            "method": operation["method"],
            "path": operation["path"],
            "timestamp": operation["timestamp"],
        },
    )
    is_agent = bool(operation.get("is_known_agent"))
    return {
        "id": f"first-time-{operation['identity']}-{operation['method']}-{operation['path']}",
        "kind": "first_time_operation",
        "severity": "medium",
        "confidence": 0.8 if is_agent else 0.6,
        "title": "First-ever operation for this identity",
        "summary": (
            f"{operation['identity']} called {operation['method']} "
            f"{operation['path']} for the first time in the current window."
        ),
        "evidence": [
            {
                "claim": "Operation is absent from the historical window",
                "citation": citation,
            }
        ],
        "counter_evidence": (
            "A declared agent may have received a new, human-approved task; an "
            "undeclared identity may be misattributed or missing from the "
            "historical log. Confirm with deployment/change records."
            if is_agent
            else "Identity is not declared as an agent; the historical log may "
            "be incomplete or the caller may be misattributed."
        ),
    }


def investigate(
    spec_path: str,
    historical_log_path: str,
    current_log_path: str,
    known_agents: list[str] | None = None,
) -> dict[str, Any]:
    """Run a deterministic, cited investigation.

    Tool sequence: `discover` (spec context), `baseline` (behavioral
    findings), and `policies_recommend` (concrete remediation artifacts).
    """
    known_agents = known_agents or []
    tool_calls: list[dict[str, Any]] = []

    inventory = json.loads(_core.discover(spec_path))
    _citation(
        tool_calls,
        "pyapicheck.discover",
        {"spec_path": spec_path},
        {
            "total_endpoints": inventory["summary"]["total_endpoints"],
            "high_or_critical": inventory["summary"]["high_or_critical"],
            "unauthenticated": inventory["summary"]["unauthenticated"],
        },
    )

    baseline_args = {
        "spec_path": spec_path,
        "historical_log_path": historical_log_path,
        "current_log_path": current_log_path,
        "known_agents": known_agents,
    }
    baseline_result = json.loads(
        _core.baseline(
            spec_path,
            historical_log_path,
            current_log_path,
            known_agents or [],
        )
    )

    known_agent_ids = {
        baseline["identity"]
        for baseline in baseline_result["baselines"]
        if baseline.get("is_known_agent")
    }
    findings: list[dict[str, Any]] = []
    for finding in baseline_result["bola_findings"]:
        findings.append(_bola_finding(finding, tool_calls, baseline_args))
    for operation in baseline_result["first_time_operations"]:
        operation = {
            **operation,
            "is_known_agent": operation["identity"] in known_agent_ids,
        }
        findings.append(_first_time_finding(operation, tool_calls, baseline_args))

    recommendations = json.loads(
        _core.policies_recommend(
            spec_path,
            historical_log_path,
            current_log_path,
            known_agents or [],
        )
    )
    if recommendations:
        _citation(
            tool_calls,
            "pyapicheck.policies_recommend",
            baseline_args,
            {"recommendations": recommendations},
        )
        recommendation_citation = len(tool_calls) - 1
        for finding in findings:
            finding["remediation"] = {
                "citation": recommendation_citation,
                "note": (
                    "See the cited recommendations for ready-to-review Cedar "
                    "forbid policies generated from this finding class."
                ),
            }

    findings.sort(key=lambda finding: (-finding["confidence"], finding["id"]))
    return {
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "spec": spec_path,
        "historical_log": historical_log_path,
        "current_log": current_log_path,
        "known_agents": known_agents,
        "tool_calls": tool_calls,
        "findings": findings,
        "limits": [
            "No LLM planner is wired in; this deterministic pass runs a fixed, "
            "documented tool sequence.",
            "No per-record resource ownership data exists in this project, so "
            "BOLA findings cannot be confirmed against ownership.",
            "Behavioral findings depend on the completeness of the supplied "
            "historical and current traffic windows.",
        ],
    }

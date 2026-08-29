"""The pyapicheck CLI: `pyapicheck discover <spec>` / `pyapicheck remediate <spec>`."""

import argparse
import difflib
import json
import os
import sys

from . import baseline as _baseline
from . import diff as _diff_specs
from . import discover as _discover_inventory
from . import discover_directory as _discover_directory
from . import graph_add_agent as _graph_add_agent
from . import graph_blast_radius as _graph_blast_radius
from . import graph_load_mcp as _graph_load_mcp
from . import graph_reachable as _graph_reachable
from . import persist as _persist
from . import remediate as _remediate_spec
from . import report as _report

_LEVEL_COLORS = {
    "CRITICAL": "\033[1;97;41m",
    "HIGH": "\033[1;31m",
    "MEDIUM": "\033[1;33m",
    "LOW": "\033[1;32m",
}
_RESET = "\033[0m"


def _colorize(level: str) -> str:
    if not sys.stdout.isatty():
        return level
    return f"{_LEVEL_COLORS.get(level, '')}{level}{_RESET}"


def _print_report(inventory: dict) -> None:
    summary = inventory["summary"]
    print(f"\n{inventory['title']} ({inventory['api_version']})")
    print(f"source: {inventory['source']}\n")
    print(
        f"{summary['total_endpoints']} endpoints discovered  |  "
        f"{summary['high_or_critical']} high/critical  |  "
        f"{summary['unauthenticated']} unauthenticated  |  "
        f"{summary['sensitive_endpoints']} touch sensitive data\n"
    )

    endpoints = sorted(
        inventory["endpoints"], key=lambda e: e["risk"]["score"], reverse=True
    )

    for ep in endpoints:
        risk = ep["risk"]
        label = _colorize(risk["level"])
        print(f"{ep['method']:<7} {ep['path']:<28} {label:<18} score={risk['score']}")
        for factor in risk["factors"]:
            print(f"    - [{factor['severity']}] {factor['description']}")
        if ep["sensitive_fields"]:
            by_name = {}
            for f in ep["sensitive_fields"]:
                entry = by_name.setdefault(f["name"], {"category": f["category"], "locations": []})
                entry["locations"].append(f["location"])
            fields = ", ".join(
                f"{name} ({info['category']}, {'+'.join(sorted(set(info['locations'])))})"
                for name, info in by_name.items()
            )
            print(f"    fields: {fields}")
        print()


def _cmd_discover(args: argparse.Namespace) -> int:
    is_directory = os.path.isdir(args.spec)
    if args.db_url and is_directory:
        print("error: --db-url is only supported for a single spec file, not a directory", file=sys.stderr)
        return 1
    try:
        if is_directory:
            inventories = _discover_directory(args.spec)
        else:
            inventories = [_discover_inventory(args.spec)]
        if args.db_url:
            inventory_id = _persist(args.db_url, args.spec)
            print(f"persisted as inventory id {inventory_id}", file=sys.stderr)
    except Exception as exc:  # surfaces parser/classification errors directly to the user
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(inventories if is_directory else inventories[0], indent=2))
    else:
        if is_directory:
            print(f"\n{len(inventories)} spec(s) found under {args.spec}")
        for inventory in inventories:
            _print_report(inventory)
        if is_directory and len(inventories) > 1:
            total_high = sum(i["summary"]["high_or_critical"] for i in inventories)
            total_endpoints = sum(i["summary"]["total_endpoints"] for i in inventories)
            print(
                f"--- aggregate: {total_endpoints} endpoints across "
                f"{len(inventories)} specs, {total_high} high/critical ---\n"
            )

    total_high_or_critical = sum(i["summary"]["high_or_critical"] for i in inventories)
    if args.fail_on_high and total_high_or_critical > 0:
        return 2
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    try:
        report = _diff_specs(args.old_spec, args.new_spec)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    print(f"\ndrift: {args.old_spec} -> {args.new_spec}\n")

    if report["added"]:
        print(f"added ({len(report['added'])}):")
        for ep in report["added"]:
            print(f"  + {ep['method']:<7} {ep['path']}")
        print()

    if report["removed"]:
        print(f"removed ({len(report['removed'])}):")
        for ep in report["removed"]:
            print(f"  - {ep['method']:<7} {ep['path']}")
        print()

    if report["changed"]:
        print(f"changed ({len(report['changed'])}):")
        for ep in report["changed"]:
            print(f"  ~ {ep['method']:<7} {ep['path']}")
            for change in ep["changes"]:
                print(f"      {change['field']}: {change['before']} -> {change['after']}")
        print()

    if not (report["added"] or report["removed"] or report["changed"]):
        print("no drift detected\n")

    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    try:
        result = _report(args.spec, args.access_log)
        if args.db_url:
            inventory_id = _persist(args.db_url, args.spec, args.access_log)
            print(f"persisted as inventory id {inventory_id}", file=sys.stderr)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    inventory = result["inventory"]
    lifecycle = result["lifecycle"]
    counts = {
        (ep["method"], ep["path"]): ep["request_count"] for ep in lifecycle["active"]
    }
    zombie_keys = {(ep["method"], ep["path"]) for ep in lifecycle["zombie"]}

    _print_report(inventory)

    print(
        f"lifecycle (from {args.access_log}): "
        f"{len(lifecycle['active'])} active, {len(lifecycle['zombie'])} zombie, "
        f"{len(lifecycle['shadow'])} shadow\n"
    )
    for ep in inventory["endpoints"]:
        key = (ep["method"], ep["path"])
        if key in zombie_keys:
            status = "ZOMBIE (0 requests observed)"
        else:
            status = f"active ({counts.get(key, 0)} requests observed)"
        print(f"  {ep['method']:<7} {ep['path']:<28} {status}")

    if lifecycle["shadow"]:
        print("\nshadow endpoints (observed traffic, not in any spec):")
        for ep in lifecycle["shadow"]:
            print(f"  {ep['method']:<7} {ep['path']:<28} {ep['request_count']} requests")
    print()

    return 0


def _cmd_remediate(args: argparse.Namespace) -> int:
    try:
        with open(args.spec, "r", encoding="utf-8") as f:
            original_text = f.read()
        plan = _remediate_spec(args.spec)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    fixes = plan["fixes"]
    if not fixes:
        print("No fixable findings (no_auth with a declared scheme, or missing_metadata).")
        return 0

    print(f"{len(fixes)} fixable finding(s):\n")
    for fix in fixes:
        print(f"  [{fix['factor_id']}] {fix['method']:<7} {fix['path']:<28} {fix['description']}")

    if args.json:
        print(json.dumps(plan, indent=2))
    else:
        diff = "".join(
            difflib.unified_diff(
                original_text.splitlines(keepends=True),
                plan["patched_spec_text"].splitlines(keepends=True),
                fromfile=f"a/{args.spec}",
                tofile=f"b/{args.spec}",
            )
        )
        print(f"\n{diff}")

    if args.apply:
        with open(args.spec, "w", encoding="utf-8") as f:
            f.write(plan["patched_spec_text"])
        print(f"\nApplied {len(fixes)} fix(es) to {args.spec}")
    else:
        print("\nDry run: no changes written. Re-run with --apply to write these changes.")

    return 0


def _cmd_baseline(args: argparse.Namespace) -> int:
    try:
        result = _baseline(
            args.spec, args.historical_log, args.current_log, known_agents=args.agent or []
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    baselines = result["baselines"]
    bola_findings = result["bola_findings"]
    first_time_ops = result["first_time_operations"]

    print(f"\n{len(baselines)} identit(y/ies) observed:\n")
    for b in baselines:
        agent_tag = " [agent]" if b["is_known_agent"] else ""
        regularity = (
            f"{b['timing_regularity']:.3f}" if b["timing_regularity"] is not None else "n/a"
        )
        print(
            f"  {b['identity']:<20}{agent_tag}  requests={b['total_requests']:<5} "
            f"resources={b['distinct_resources']:<4} error_rate={b['error_rate']:.2f} "
            f"req/min={b['requests_per_minute']:.2f} timing_cv={regularity}"
        )

    if bola_findings:
        print(f"\n{len(bola_findings)} BOLA-shaped finding(s) (sequential ID access):")
        for f in bola_findings:
            print(
                f"  {f['identity']:<20} {f['method']:<7} {f['path_template']:<28} "
                f"run of {f['run_length']} sequential IDs: {f['accessed_ids']}"
            )

    if first_time_ops:
        print(f"\n{len(first_time_ops)} first-time-observed operation(s):")
        for op in first_time_ops:
            ts = f" at {op['timestamp']}" if op["timestamp"] else ""
            print(f"  {op['identity']:<20} {op['method']:<7} {op['path']}{ts}")

    print()
    return 0


def _cmd_graph_load_mcp(args: argparse.Namespace) -> int:
    try:
        servers = _graph_load_mcp(args.db_url, args.config, args.timeout)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(servers, indent=2))
        return 0

    for server in servers:
        config = server["config"]
        tools = server["tools"]
        if "Tools" in tools:
            status = f"{len(tools['Tools'])} tool(s): {', '.join(tools['Tools'])}"
        else:
            status = f"unavailable: {tools['Unavailable']}"
        print(f"  {config['name']:<20} {status}")
    print(f"\n{len(servers)} MCP server(s) written to the graph")
    return 0


def _cmd_graph_add_agent(args: argparse.Namespace) -> int:
    try:
        _graph_add_agent(
            args.db_url,
            args.name,
            args.owner,
            allowed_tools=args.tool or [],
            allowed_apis=args.api or [],
            declared_scope=args.scope or "",
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"agent {args.name!r} written to the graph")
    return 0


def _cmd_graph_reachable(args: argparse.Namespace) -> int:
    try:
        nodes = _graph_reachable(args.db_url, args.agent_name)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(nodes, indent=2))
        return 0

    print(f"\n{args.agent_name} can reach {len(nodes)} node(s):")
    for node in nodes:
        print(f"  {node['label']:<12} {node['name']}")
    return 0


def _cmd_graph_blast_radius(args: argparse.Namespace) -> int:
    try:
        nodes = _graph_blast_radius(args.db_url, args.resource_name)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(nodes, indent=2))
        return 0

    print(f"\n{len(nodes)} identit(y/ies) can reach {args.resource_name}:")
    for node in nodes:
        print(f"  {node['label']:<12} {node['name']}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="pyapicheck")
    sub = parser.add_subparsers(dest="command", required=True)

    discover_parser = sub.add_parser(
        "discover",
        help="Discover a risk-scored API inventory from a spec file or a directory of specs",
    )
    discover_parser.add_argument(
        "spec",
        help=(
            "Path to an OpenAPI 3.x YAML/JSON file, a Postman Collection v2.1 JSON "
            "export, or a directory to search recursively for either"
        ),
    )
    discover_parser.add_argument(
        "--json", action="store_true", help="Output raw JSON instead of a report"
    )
    discover_parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Exit non-zero if any endpoint scores HIGH or CRITICAL (for CI)",
    )
    discover_parser.add_argument(
        "--db-url",
        default=None,
        help="Postgres URL to persist this inventory to, in addition to printing it (single spec file only)",
    )
    discover_parser.set_defaults(func=_cmd_discover)

    remediate_parser = sub.add_parser(
        "remediate",
        help="Generate (and optionally apply) safe, mechanical spec fixes for fixable findings",
    )
    remediate_parser.add_argument("spec", help="Path to an OpenAPI 3.x YAML or JSON file")
    remediate_parser.add_argument(
        "--apply", action="store_true", help="Write the patched spec back to `spec` (default: dry-run)"
    )
    remediate_parser.add_argument(
        "--json", action="store_true", help="Also print the full remediation plan as JSON"
    )
    remediate_parser.set_defaults(func=_cmd_remediate)

    diff_parser = sub.add_parser(
        "diff", help="Diff two spec snapshots and report added/removed/changed endpoints"
    )
    diff_parser.add_argument("old_spec", help="Path to the older OpenAPI 3.x YAML or JSON file")
    diff_parser.add_argument("new_spec", help="Path to the newer OpenAPI 3.x YAML or JSON file")
    diff_parser.add_argument(
        "--json", action="store_true", help="Output the raw drift report as JSON"
    )
    diff_parser.set_defaults(func=_cmd_diff)

    report_parser = sub.add_parser(
        "report",
        help="Cross-reference a spec against a gateway access log for shadow/zombie endpoints",
    )
    report_parser.add_argument("spec", help="Path to an OpenAPI 3.x YAML or JSON file")
    report_parser.add_argument(
        "access_log", help="Path to an NDJSON gateway access log (NGINX- or Envoy-shaped)"
    )
    report_parser.add_argument(
        "--json", action="store_true", help="Output the raw inventory + lifecycle report as JSON"
    )
    report_parser.add_argument(
        "--db-url",
        default=None,
        help="Postgres URL to persist this inventory + traffic to, in addition to printing it",
    )
    report_parser.set_defaults(func=_cmd_report)

    baseline_parser = sub.add_parser(
        "baseline",
        help="Per-identity behavioral baselines, BOLA-shaped findings, and first-time operations",
    )
    baseline_parser.add_argument("spec", help="Path to an OpenAPI 3.x YAML or JSON file")
    baseline_parser.add_argument(
        "historical_log", help="Path to an NDJSON gateway access log covering the baseline window"
    )
    baseline_parser.add_argument(
        "current_log", help="Path to an NDJSON gateway access log covering the window to evaluate"
    )
    baseline_parser.add_argument(
        "--agent",
        action="append",
        help="Identity known to be a declared agent, not inferred from timing (repeatable)",
    )
    baseline_parser.add_argument(
        "--json", action="store_true", help="Output the raw baseline report as JSON"
    )
    baseline_parser.set_defaults(func=_cmd_baseline)

    graph_parser = sub.add_parser(
        "graph", help="Security graph: MCP/agent discovery, reachability, blast radius"
    )
    graph_sub = graph_parser.add_subparsers(dest="graph_command", required=True)

    load_mcp_parser = graph_sub.add_parser(
        "load-mcp", help="Discover MCP servers from a config file and write them into the graph"
    )
    load_mcp_parser.add_argument(
        "config", help="Path to an mcpServers-shaped config (claude_desktop_config.json / .mcp.json)"
    )
    load_mcp_parser.add_argument("--db-url", required=True, help="Postgres+AGE URL")
    load_mcp_parser.add_argument(
        "--timeout", type=int, default=10, help="Seconds to wait for each server's tools/list response"
    )
    load_mcp_parser.add_argument("--json", action="store_true", help="Output raw JSON")
    load_mcp_parser.set_defaults(func=_cmd_graph_load_mcp)

    add_agent_parser = graph_sub.add_parser(
        "add-agent", help="Write an agent identity into the graph, linked to its declared tools/APIs"
    )
    add_agent_parser.add_argument("name", help="Agent name")
    add_agent_parser.add_argument("--owner", required=True, help="Who owns/is responsible for this agent")
    add_agent_parser.add_argument(
        "--tool", action="append", help="Name of a Tool vertex this agent can call (repeatable)"
    )
    add_agent_parser.add_argument(
        "--api", action="append", help="Name of an Endpoint vertex this agent can call (repeatable)"
    )
    add_agent_parser.add_argument("--scope", default="", help="Declared scope, free text")
    add_agent_parser.add_argument("--db-url", required=True, help="Postgres+AGE URL")
    add_agent_parser.set_defaults(func=_cmd_graph_add_agent)

    reachable_parser = graph_sub.add_parser(
        "reachable", help="What can this agent reach (multi-hop traversal)"
    )
    reachable_parser.add_argument("agent_name", help="Agent name")
    reachable_parser.add_argument("--db-url", required=True, help="Postgres+AGE URL")
    reachable_parser.add_argument("--json", action="store_true", help="Output raw JSON")
    reachable_parser.set_defaults(func=_cmd_graph_reachable)

    blast_radius_parser = graph_sub.add_parser(
        "blast-radius", help="What can reach this resource (reverse multi-hop traversal)"
    )
    blast_radius_parser.add_argument("resource_name", help="Resource (or any vertex) name")
    blast_radius_parser.add_argument("--db-url", required=True, help="Postgres+AGE URL")
    blast_radius_parser.add_argument("--json", action="store_true", help="Output raw JSON")
    blast_radius_parser.set_defaults(func=_cmd_graph_blast_radius)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

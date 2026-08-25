"""The pyapicheck CLI: `pyapicheck discover <spec>` / `pyapicheck remediate <spec>`."""

import argparse
import difflib
import json
import sys

from . import discover as _discover_inventory
from . import remediate as _remediate_spec

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
    try:
        inventory = _discover_inventory(args.spec)
    except Exception as exc:  # surfaces parser/classification errors directly to the user
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(inventory, indent=2))
    else:
        _print_report(inventory)

    if args.fail_on_high and inventory["summary"]["high_or_critical"] > 0:
        return 2
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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="pyapicheck")
    sub = parser.add_subparsers(dest="command", required=True)

    discover_parser = sub.add_parser(
        "discover", help="Discover a risk-scored API inventory from an OpenAPI spec"
    )
    discover_parser.add_argument("spec", help="Path to an OpenAPI 3.x YAML or JSON file")
    discover_parser.add_argument(
        "--json", action="store_true", help="Output raw JSON instead of a report"
    )
    discover_parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Exit non-zero if any endpoint scores HIGH or CRITICAL (for CI)",
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

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

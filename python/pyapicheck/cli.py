"""The pyapicheck CLI: `pyapicheck discover <spec>`."""

import argparse
import json
import sys

from . import discover as _discover_inventory

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

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Minimal fixture MCP server for pyapicheck's live tool-discovery
integration test (core/src/mcp.rs). Speaks just enough real MCP JSON-RPC
over stdio -- initialize, notifications/initialized, tools/list -- to let
the test spawn a real subprocess and read back a real tool list, rather
than mocking the transport."""

import json
import sys

TOOLS = [
    {"name": "list_refunds", "description": "List pending refunds"},
    {"name": "process_refund", "description": "Process a refund"},
]


def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = request.get("method")
        request_id = request.get("id")

        if method == "initialize":
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "serverInfo": {"name": "fixture-mcp-server", "version": "0.0.0"},
                    },
                }
            )
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}})
        elif request_id is not None:
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"method not found: {method}"},
                }
            )


if __name__ == "__main__":
    main()

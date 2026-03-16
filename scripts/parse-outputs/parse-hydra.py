#!/usr/bin/env python3
"""
parse-hydra.py -- Convert Hydra JSON output to normalized JSON.

Called by the hydra-wrapper.sh script and the parse_hydra_output MCP tool.
Takes a Hydra JSON output file (produced with -b json) and produces a
normalized JSON document suitable for LLM analysis in the ORGA Reason phase.

Hydra JSON format (with -b json):
{
    "generator": {
        "software": "THC-Hydra",
        "jsonoutputversion": "1.00",
        ...
    },
    "results": [
        {
            "host": "192.168.1.1",
            "port": 22,
            "login": "admin",
            "password": "password123",
            "service": "ssh"
        },
        ...
    ]
}

Normalized output:
{
    "target": "192.168.1.1",
    "service": "ssh",
    "credentials_found": 2,
    "credentials": [
        {
            "host": "192.168.1.1",
            "port": 22,
            "username": "admin",
            "password": "password123",
            "service": "ssh"
        },
        ...
    ]
}
"""

import json
import sys


def parse_hydra_json(json_path: str) -> dict:
    """Parse Hydra JSON output into a normalized dict."""
    with open(json_path, "r") as f:
        raw = json.load(f)

    results = raw.get("results", [])

    # Determine the primary target and service from the first result,
    # falling back to empty strings if no results exist
    target = ""
    service = ""
    if results:
        target = results[0].get("host", "")
        service = results[0].get("service", "")

    # Normalize each credential entry
    credentials = []
    for result in results:
        credential = {
            "host": result.get("host", ""),
            "port": int(result.get("port", 0)),
            "username": result.get("login", ""),
            "password": result.get("password", ""),
            "service": result.get("service", ""),
        }
        credentials.append(credential)

        # Update target/service if we haven't set them yet
        if not target:
            target = credential["host"]
        if not service:
            service = credential["service"]

    return {
        "target": target,
        "service": service,
        "credentials_found": len(credentials),
        "credentials": credentials,
    }


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: parse-hydra.py <json_file>"}))
        sys.exit(1)

    json_path = sys.argv[1]

    try:
        result = parse_hydra_json(json_path)
        print(json.dumps(result, indent=2))
    except json.JSONDecodeError as e:
        print(json.dumps({
            "error": f"JSON parse error: {e}",
            "target": "",
            "service": "",
            "credentials_found": 0,
            "credentials": [],
        }))
        sys.exit(1)
    except FileNotFoundError:
        print(json.dumps({
            "error": f"File not found: {json_path}",
            "target": "",
            "service": "",
            "credentials_found": 0,
            "credentials": [],
        }))
        sys.exit(1)
    except KeyError as e:
        print(json.dumps({
            "error": f"Missing expected key in Hydra output: {e}",
            "target": "",
            "service": "",
            "credentials_found": 0,
            "credentials": [],
        }))
        sys.exit(1)


if __name__ == "__main__":
    main()

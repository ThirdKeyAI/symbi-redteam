#!/usr/bin/env python3
"""
parse-nikto.py -- Convert Nikto JSON output to normalized structured JSON.

Called by the Symbiont runtime after a nikto_scan completes. Takes a Nikto
JSON output file and produces a normalized JSON document suitable for LLM
analysis in the ORGA Reason phase.

The parser extracts:
  - Scan metadata (target, start time, options)
  - Individual findings with ID, URL, method, description, references
  - Summary statistics

Nikto JSON output format (array of objects):
  [
    {
      "host": "10.0.1.5",
      "ip": "10.0.1.5",
      "port": "80",
      "banner": "Apache/2.4.49",
      "vulnerabilities": [
        {
          "id": "000726",
          "OSVDB": "0",
          "method": "GET",
          "url": "/index.html",
          "msg": "...",
          "references": "..."
        },
        ...
      ]
    }
  ]
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def parse_nikto_json(json_path: str) -> dict:
    """Parse Nikto JSON output into a normalized dict."""
    file_path = Path(json_path)

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        raw_content = f.read().strip()

    # Nikto may output invalid JSON or wrapped formats; handle gracefully
    try:
        raw_data = json.loads(raw_content)
    except json.JSONDecodeError:
        # Try to extract JSON from potential wrapper text
        # Nikto sometimes prepends non-JSON lines
        lines = raw_content.split("\n")
        json_lines = []
        in_json = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("[") or stripped.startswith("{"):
                in_json = True
            if in_json:
                json_lines.append(line)

        if json_lines:
            try:
                raw_data = json.loads("\n".join(json_lines))
            except json.JSONDecodeError as e:
                return {
                    "error": f"Failed to parse Nikto JSON output: {e}",
                    "raw_length": len(raw_content),
                }
        else:
            return {
                "error": "No JSON content found in Nikto output",
                "raw_length": len(raw_content),
            }

    # Normalize: Nikto output can be a list of host results or a single object
    if isinstance(raw_data, dict):
        host_results = [raw_data]
    elif isinstance(raw_data, list):
        host_results = raw_data
    else:
        return {"error": f"Unexpected Nikto output type: {type(raw_data).__name__}"}

    all_findings = []
    scan_info = {
        "target": "",
        "ip": "",
        "port": "",
        "banner": "",
        "start_time": datetime.now(timezone.utc).isoformat(),
        "source_file": str(file_path),
    }

    for host_result in host_results:
        if not isinstance(host_result, dict):
            continue

        # Extract scan metadata from the first host result
        if not scan_info["target"]:
            scan_info["target"] = host_result.get("host", "")
            scan_info["ip"] = host_result.get("ip", "")
            scan_info["port"] = str(host_result.get("port", ""))
            scan_info["banner"] = host_result.get("banner", "")

        # Extract vulnerabilities/findings
        vulns = host_result.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            continue

        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue

            finding = {
                "id": str(vuln.get("id", "")),
                "osvdb": str(vuln.get("OSVDB", vuln.get("osvdb", "0"))),
                "method": vuln.get("method", "GET"),
                "url": vuln.get("url", vuln.get("uri", "")),
                "description": vuln.get("msg", vuln.get("message", "")),
                "references": parse_references(
                    vuln.get("references", vuln.get("refs", ""))
                ),
            }
            all_findings.append(finding)

    return {
        "scan_info": scan_info,
        "findings_count": len(all_findings),
        "findings": all_findings,
    }


def parse_references(refs_value) -> list:
    """Normalize references into a list of strings."""
    if isinstance(refs_value, list):
        return [str(r) for r in refs_value]
    if isinstance(refs_value, str):
        if not refs_value or refs_value.strip() == "":
            return []
        # References may be comma or space separated
        parts = [r.strip() for r in refs_value.replace(",", " ").split()]
        return [p for p in parts if p]
    return []


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: parse-nikto.py <json_file>"}))
        sys.exit(1)

    json_path = sys.argv[1]

    try:
        result = parse_nikto_json(json_path)
        print(json.dumps(result, indent=2))
    except FileNotFoundError:
        print(json.dumps({"error": f"File not found: {json_path}"}))
        sys.exit(1)
    except PermissionError:
        print(json.dumps({"error": f"Permission denied: {json_path}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
parse-nuclei.py -- Convert Nuclei JSONL output to structured JSON.

Called by the nuclei_scan MCP tool. Takes a Nuclei JSONL output file and
produces a JSON document suitable for LLM analysis in the ORGA Reason phase.

Nuclei outputs one JSON object per line (JSONL format). Each line represents
a single finding from a template match.

The parser extracts:
  - Template ID and name
  - Severity level
  - Matched URL/endpoint
  - Description and references
  - Curl command for reproduction

Usage:
    parse-nuclei.py <jsonl_file> [target]
"""

import json
import sys


def parse_nuclei_jsonl(jsonl_path: str, target: str = "") -> dict:
    """Parse Nuclei JSONL output into a structured dict."""
    findings = []
    templates_seen = set()

    try:
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    # Log malformed lines but continue parsing
                    print(
                        f"WARNING: Skipping malformed JSON on line {line_num}: {e}",
                        file=sys.stderr,
                    )
                    continue

                finding = normalize_finding(entry)
                if finding:
                    findings.append(finding)
                    templates_seen.add(finding["template_id"])

    except FileNotFoundError:
        return {
            "error": f"File not found: {jsonl_path}",
            "target": target,
            "templates_used": [],
            "findings_count": 0,
            "findings": [],
        }

    return {
        "target": target,
        "templates_used": sorted(templates_seen),
        "findings_count": len(findings),
        "findings": findings,
    }


def normalize_finding(entry: dict) -> dict:
    """Normalize a single Nuclei JSONL entry into our standard format."""
    # Nuclei JSONL structure varies slightly by version but core fields
    # are consistent. We handle both v2 and v3 output formats.

    # Extract template info
    template_id = entry.get("template-id", entry.get("templateID", ""))
    info = entry.get("info", {})
    name = info.get("name", entry.get("name", ""))
    severity = info.get("severity", entry.get("severity", "unknown"))
    description = info.get("description", entry.get("description", ""))

    # Extract match info
    matched_at = entry.get("matched-at", entry.get("matched", entry.get("host", "")))

    # Extract references -- can be a list or a dict with url/cwe/cve keys
    raw_refs = info.get("reference", entry.get("reference", []))
    if isinstance(raw_refs, dict):
        references = []
        for key in ("url", "cve", "cwe"):
            val = raw_refs.get(key, [])
            if isinstance(val, list):
                references.extend(val)
            elif isinstance(val, str) and val:
                references.append(val)
    elif isinstance(raw_refs, list):
        references = [str(r) for r in raw_refs if r]
    elif isinstance(raw_refs, str) and raw_refs:
        references = [raw_refs]
    else:
        references = []

    # Extract curl command for reproduction
    curl_command = entry.get("curl-command", entry.get("curl_command", ""))

    # If no curl command, try to reconstruct from request data
    if not curl_command:
        request = entry.get("request", "")
        if request and matched_at:
            # Simple reconstruction -- just note the endpoint
            curl_command = f"curl -s '{matched_at}'"

    if not template_id and not name:
        return {}

    return {
        "template_id": template_id,
        "name": name,
        "severity": severity.lower() if isinstance(severity, str) else "unknown",
        "matched_at": matched_at,
        "description": description,
        "reference": references,
        "curl_command": curl_command,
    }


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: parse-nuclei.py <jsonl_file> [target]"}))
        sys.exit(1)

    jsonl_path = sys.argv[1]
    target = sys.argv[2] if len(sys.argv) > 2 else ""

    result = parse_nuclei_jsonl(jsonl_path, target)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

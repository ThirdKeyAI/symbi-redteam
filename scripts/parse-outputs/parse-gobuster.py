#!/usr/bin/env python3
"""
parse-gobuster.py -- Convert Gobuster output to structured JSON.

Called by the Symbiont runtime after a gobuster_scan completes. Takes a
Gobuster text output file and produces a JSON document suitable for LLM
analysis in the ORGA Reason phase.

Gobuster dir mode output format (one entry per line):
  /path                 (Status: 200) [Size: 1234]
  /admin                (Status: 301) [Size: 0]
  /uploads              (Status: 403) [Size: 287]

Gobuster dns mode output format:
  Found: subdomain.example.com

Gobuster vhost mode output format:
  Found: dev.example.com (Status: 200) [Size: 5432]
"""

import json
import re
import sys
from pathlib import Path


def parse_gobuster_output(output_path: str) -> dict:
    """Parse Gobuster output into a structured dict."""
    file_path = Path(output_path)

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    # Detect mode from content patterns
    mode = detect_mode(lines)

    if mode == "dir":
        entries = parse_dir_mode(lines)
    elif mode == "dns":
        entries = parse_dns_mode(lines)
    elif mode == "vhost":
        entries = parse_vhost_mode(lines)
    else:
        entries = parse_dir_mode(lines)  # fallback

    # Extract target from the output if possible
    target = extract_target(lines)

    return {
        "target": target,
        "mode": mode,
        "source_file": str(file_path),
        "entries_count": len(entries),
        "entries": entries,
    }


def detect_mode(lines: list) -> str:
    """Detect gobuster mode from output content."""
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        # DNS mode: lines start with "Found: "
        if stripped.startswith("Found:") and "(Status:" not in stripped:
            return "dns"
        # Vhost mode: "Found: host (Status: ...)"
        if stripped.startswith("Found:") and "(Status:" in stripped:
            return "vhost"
        # Dir mode: lines with paths and status codes
        if re.match(r"^/\S+\s+\(Status:\s*\d+\)", stripped):
            return "dir"
        # Dir mode variant: gobuster -o output may just have the path and status
        if re.match(r"^/\S+", stripped):
            return "dir"
    return "dir"


def parse_dir_mode(lines: list) -> list:
    """Parse directory brute-force output."""
    entries = []
    # Pattern: /path                 (Status: 200) [Size: 1234]
    dir_pattern = re.compile(
        r"^(/\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?"
    )
    # Alternate pattern for simpler output: just path and status
    simple_pattern = re.compile(r"^(/\S+)\s+(\d{3})\s+(\d+)?")

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("="):
            continue

        match = dir_pattern.match(stripped)
        if match:
            entry = {
                "path": match.group(1),
                "status": int(match.group(2)),
                "size": int(match.group(3)) if match.group(3) else 0,
            }
            entries.append(entry)
            continue

        match = simple_pattern.match(stripped)
        if match:
            entry = {
                "path": match.group(1),
                "status": int(match.group(2)),
                "size": int(match.group(3)) if match.group(3) else 0,
            }
            entries.append(entry)

    return entries


def parse_dns_mode(lines: list) -> list:
    """Parse DNS subdomain enumeration output."""
    entries = []
    dns_pattern = re.compile(r"^Found:\s+(\S+)")

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        match = dns_pattern.match(stripped)
        if match:
            entries.append({
                "hostname": match.group(1),
                "status": 0,
                "size": 0,
            })

    return entries


def parse_vhost_mode(lines: list) -> list:
    """Parse virtual host discovery output."""
    entries = []
    vhost_pattern = re.compile(
        r"^Found:\s+(\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?"
    )

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        match = vhost_pattern.match(stripped)
        if match:
            entries.append({
                "hostname": match.group(1),
                "status": int(match.group(2)),
                "size": int(match.group(3)) if match.group(3) else 0,
            })

    return entries


def extract_target(lines: list) -> str:
    """Try to extract the target URL/domain from gobuster output header."""
    target_pattern = re.compile(r"(?:Url|Target):\s+(\S+)", re.IGNORECASE)
    for line in lines[:20]:  # Check first 20 lines for header info
        match = target_pattern.search(line)
        if match:
            return match.group(1)
    return ""


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: parse-gobuster.py <output_file>"}))
        sys.exit(1)

    output_path = sys.argv[1]

    try:
        result = parse_gobuster_output(output_path)
        print(json.dumps(result, indent=2))
    except FileNotFoundError:
        print(json.dumps({"error": f"File not found: {output_path}"}))
        sys.exit(1)
    except PermissionError:
        print(json.dumps({"error": f"Permission denied: {output_path}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()

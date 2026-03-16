#!/usr/bin/env python3
"""
parse-sqlmap.py -- Convert sqlmap output directory to structured JSON.

Called by the sqlmap_detect and sqlmap_exploit MCP tools. Takes a sqlmap
output directory and produces a JSON document suitable for LLM analysis
in the ORGA Reason phase.

SQLmap outputs to a directory structure:
    output_dir/
        target_host/
            log           -- main scan log with injection details
            dump/          -- extracted data (exploit mode only)
                db_name/
                    table.csv

The parser extracts:
  - Vulnerability status
  - Injection points (parameter, type, title, payload)
  - Discovered databases (exploit mode)
  - Extracted tables (exploit mode)

Usage:
    parse-sqlmap.py <output_dir> [target_url] [method]
"""

import csv
import json
import os
import re
import sys
from pathlib import Path


def parse_sqlmap_output(output_dir: str, target_url: str = "", method: str = "GET") -> dict:
    """Parse sqlmap output directory into a structured dict."""
    result = {
        "target_url": target_url,
        "method": method,
        "vulnerable": False,
        "injection_points": [],
        "databases": [],
        "tables": {},
    }

    output_path = Path(output_dir)
    if not output_path.exists():
        result["error"] = f"Output directory not found: {output_dir}"
        return result

    # Find the log file -- sqlmap creates a subdirectory named after the target host
    log_file = find_log_file(output_path)
    if log_file:
        injection_points, vulnerable = parse_log_file(log_file)
        result["injection_points"] = injection_points
        result["vulnerable"] = vulnerable
    else:
        # Check the run log as fallback
        run_log = output_path / "sqlmap-run.log"
        if run_log.exists():
            injection_points, vulnerable = parse_run_log(run_log)
            result["injection_points"] = injection_points
            result["vulnerable"] = vulnerable

    # Parse dump directory for extracted data (exploit mode only)
    databases, tables = parse_dump_directory(output_path)
    result["databases"] = databases
    result["tables"] = tables

    return result


def find_log_file(output_path: Path) -> Path | None:
    """Find the sqlmap log file within the output directory."""
    # sqlmap creates: output_dir/hostname/log
    for child in output_path.iterdir():
        if child.is_dir() and child.name != "dump":
            log_candidate = child / "log"
            if log_candidate.exists():
                return log_candidate

    # Direct log file
    direct_log = output_path / "log"
    if direct_log.exists():
        return direct_log

    return None


def parse_log_file(log_path: Path) -> tuple[list[dict], bool]:
    """Parse sqlmap's log file for injection points."""
    injection_points = []
    vulnerable = False

    try:
        content = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return injection_points, vulnerable

    # Check for vulnerability confirmation
    if "is vulnerable" in content or "sqlmap identified the following injection point" in content:
        vulnerable = True

    # Parse injection point blocks
    # sqlmap logs injection points in a structured format:
    #   Parameter: id (GET)
    #       Type: boolean-based blind
    #       Title: AND boolean-based blind - WHERE or HAVING clause
    #       Payload: id=1 AND 1234=1234
    current_param = ""
    current_type = ""
    current_title = ""

    for line in content.splitlines():
        line = line.strip()

        # Match parameter line: "Parameter: name (METHOD)"
        param_match = re.match(r"Parameter:\s+(.+?)(?:\s+\((\w+)\))?$", line)
        if param_match:
            current_param = param_match.group(1)
            continue

        # Match type line
        type_match = re.match(r"Type:\s+(.+)$", line)
        if type_match:
            current_type = type_match.group(1)
            continue

        # Match title line
        title_match = re.match(r"Title:\s+(.+)$", line)
        if title_match:
            current_title = title_match.group(1)
            continue

        # Match payload line -- this completes an injection point entry
        payload_match = re.match(r"Payload:\s+(.+)$", line)
        if payload_match and current_param:
            injection_points.append({
                "parameter": current_param,
                "type": current_type,
                "title": current_title,
                "payload": payload_match.group(1),
            })
            # Reset type/title for next entry under same parameter
            current_type = ""
            current_title = ""

    return injection_points, vulnerable


def parse_run_log(run_log_path: Path) -> tuple[list[dict], bool]:
    """Parse the sqlmap run log (captured stdout/stderr) as fallback."""
    injection_points = []
    vulnerable = False

    try:
        content = run_log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return injection_points, vulnerable

    if "is vulnerable" in content or "sqlmap identified the following injection point" in content:
        vulnerable = True

    # The run log has the same format as the structured log, just with
    # additional noise. Use the same parsing logic.
    current_param = ""
    current_type = ""
    current_title = ""

    for line in content.splitlines():
        # Strip sqlmap's prefix markers like [INFO], [WARNING], etc.
        line = re.sub(r"^\[\d{2}:\d{2}:\d{2}\]\s*\[\w+\]\s*", "", line).strip()

        param_match = re.match(r"Parameter:\s+(.+?)(?:\s+\((\w+)\))?$", line)
        if param_match:
            current_param = param_match.group(1)
            continue

        type_match = re.match(r"Type:\s+(.+)$", line)
        if type_match:
            current_type = type_match.group(1)
            continue

        title_match = re.match(r"Title:\s+(.+)$", line)
        if title_match:
            current_title = title_match.group(1)
            continue

        payload_match = re.match(r"Payload:\s+(.+)$", line)
        if payload_match and current_param:
            injection_points.append({
                "parameter": current_param,
                "type": current_type,
                "title": current_title,
                "payload": payload_match.group(1),
            })
            current_type = ""
            current_title = ""

    return injection_points, vulnerable


def parse_dump_directory(output_path: Path) -> tuple[list[str], dict]:
    """Parse sqlmap dump directory for extracted databases and tables."""
    databases = []
    tables = {}

    # Look for dump directories: output_dir/hostname/dump/db_name/table.csv
    for child in output_path.iterdir():
        if not child.is_dir():
            continue

        dump_dir = child / "dump"
        if not dump_dir.exists():
            continue

        for db_dir in dump_dir.iterdir():
            if not db_dir.is_dir():
                continue

            db_name = db_dir.name
            databases.append(db_name)
            tables[db_name] = {}

            for table_file in db_dir.iterdir():
                if table_file.suffix == ".csv" and table_file.is_file():
                    table_name = table_file.stem
                    table_data = parse_csv_dump(table_file)
                    tables[db_name][table_name] = table_data

    # Also check direct dump directory (no hostname subdirectory)
    direct_dump = output_path / "dump"
    if direct_dump.exists() and direct_dump.is_dir():
        for db_dir in direct_dump.iterdir():
            if not db_dir.is_dir():
                continue

            db_name = db_dir.name
            if db_name not in databases:
                databases.append(db_name)
            if db_name not in tables:
                tables[db_name] = {}

            for table_file in db_dir.iterdir():
                if table_file.suffix == ".csv" and table_file.is_file():
                    table_name = table_file.stem
                    table_data = parse_csv_dump(table_file)
                    tables[db_name][table_name] = table_data

    return sorted(databases), tables


def parse_csv_dump(csv_path: Path) -> dict:
    """Parse a sqlmap CSV dump file into a structured dict."""
    result = {
        "columns": [],
        "row_count": 0,
        "sample_rows": [],
    }

    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)

            # First row is headers
            try:
                headers = next(reader)
                result["columns"] = headers
            except StopIteration:
                return result

            # Read rows (limit to 100 sample rows for LLM context efficiency)
            rows = []
            for i, row in enumerate(reader):
                if i >= 100:
                    break
                rows.append(row)

            result["row_count"] = len(rows)
            result["sample_rows"] = rows

    except OSError:
        result["error"] = f"Could not read: {csv_path}"

    return result


def main():
    if len(sys.argv) < 2:
        print(json.dumps({
            "error": "Usage: parse-sqlmap.py <output_dir> [target_url] [method]"
        }))
        sys.exit(1)

    output_dir = sys.argv[1]
    target_url = sys.argv[2] if len(sys.argv) > 2 else ""
    method = sys.argv[3] if len(sys.argv) > 3 else "GET"

    result = parse_sqlmap_output(output_dir, target_url, method)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

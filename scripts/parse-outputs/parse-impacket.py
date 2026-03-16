#!/usr/bin/env python3
"""
parse-impacket.py -- Parse Impacket tool output into structured JSON.

Called by the post-exploitation toolchain. Takes an Impacket output file and
produces a JSON document suitable for LLM analysis in the ORGA Reason phase.

The parser handles output from all supported Impacket techniques:
  - psexec: Service-based execution output
  - wmiexec: WMI-based execution output
  - smbexec: SMB-based execution output
  - atexec: Task Scheduler execution output
  - dcomexec: DCOM-based execution output

Each technique has slightly different output formatting, but common patterns:
  - "[*]" prefix for informational messages
  - "[!]" prefix for warnings
  - "[-]" prefix for errors
  - "[+]" prefix for success messages
  - Command output appears between info/status lines
"""

import json
import re
import sys


def parse_impacket_output(output_path: str, target: str = "", technique: str = "") -> dict:
    """Parse Impacket output file into a structured dict."""
    try:
        with open(output_path, "r", encoding="utf-8", errors="replace") as f:
            raw_output = f.read()
    except FileNotFoundError:
        return {
            "target": target,
            "technique": technique,
            "success": False,
            "command_output": "",
            "errors": [f"Output file not found: {output_path}"],
        }
    except PermissionError:
        return {
            "target": target,
            "technique": technique,
            "success": False,
            "command_output": "",
            "errors": [f"Permission denied reading: {output_path}"],
        }

    lines = raw_output.splitlines()

    info_lines = []
    error_lines = []
    warning_lines = []
    success_lines = []
    command_output_lines = []
    success = False

    # Track whether we are inside the command output section
    in_command_output = False

    for line in lines:
        stripped = line.strip()
        if not stripped:
            if in_command_output:
                command_output_lines.append("")
            continue

        # Classify lines by prefix
        if stripped.startswith("[*]"):
            info_lines.append(stripped[3:].strip())
            # Detect start of command output section
            # psexec/smbexec: "Trying protocol..." or "Process ... created"
            # wmiexec: output starts after connection info
            if _is_output_boundary(stripped):
                in_command_output = True
                continue
            in_command_output = False

        elif stripped.startswith("[!]"):
            warning_lines.append(stripped[3:].strip())
            in_command_output = False

        elif stripped.startswith("[-]"):
            error_lines.append(stripped[3:].strip())
            in_command_output = False

        elif stripped.startswith("[+]"):
            success_lines.append(stripped[3:].strip())
            success = True
            in_command_output = False

        elif stripped.startswith("Impacket v"):
            # Version banner, skip
            continue

        else:
            # Anything not prefixed is likely command output
            command_output_lines.append(stripped)

    # Determine success based on various indicators
    if not success:
        success = _detect_success(info_lines, error_lines, command_output_lines, technique)

    # Clean up command output
    command_output = "\n".join(command_output_lines).strip()

    # Compile all error messages
    errors = []
    for err in error_lines:
        errors.append(err)
    for warn in warning_lines:
        if _is_critical_warning(warn):
            errors.append(f"WARNING: {warn}")

    return {
        "target": target,
        "technique": technique,
        "success": success,
        "command_output": command_output,
        "errors": errors,
    }


def _is_output_boundary(line: str) -> bool:
    """Detect lines that indicate the start of command output."""
    boundary_patterns = [
        r"\[\*\]\s*Trying protocol",
        r"\[\*\]\s*Process .+ created",
        r"\[\*\]\s*Opening SVCManager",
        r"\[\*\]\s*Creating service",
        r"\[\*\]\s*Starting service",
        r"\[\*\]\s*Executing command",
        r"\[\*\]\s*Output:",
    ]
    for pattern in boundary_patterns:
        if re.search(pattern, line):
            return True
    return False


def _detect_success(
    info_lines: list,
    error_lines: list,
    command_output_lines: list,
    technique: str,
) -> bool:
    """Heuristically determine if the execution was successful."""
    # If there are errors, likely failed
    if error_lines:
        # Check for authentication failures
        for err in error_lines:
            if any(keyword in err.lower() for keyword in [
                "access denied",
                "logon failure",
                "status_logon_failure",
                "authentication failed",
                "connection refused",
                "status_access_denied",
            ]):
                return False

    # If we got command output, likely succeeded
    if command_output_lines:
        non_empty = [l for l in command_output_lines if l.strip()]
        if non_empty:
            return True

    # Check info lines for success indicators
    for info in info_lines:
        if any(keyword in info.lower() for keyword in [
            "process created",
            "service started",
            "executing command",
            "command executed",
        ]):
            return True

    # No definitive indicators
    return len(error_lines) == 0


def _is_critical_warning(warning: str) -> bool:
    """Determine if a warning should be escalated to an error."""
    critical_keywords = [
        "timeout",
        "connection reset",
        "broken pipe",
        "session expired",
        "authentication",
    ]
    warning_lower = warning.lower()
    return any(keyword in warning_lower for keyword in critical_keywords)


def main():
    if len(sys.argv) < 2:
        print(json.dumps({
            "error": "Usage: parse-impacket.py <output_file> [target] [technique]"
        }))
        sys.exit(1)

    output_path = sys.argv[1]
    target = sys.argv[2] if len(sys.argv) > 2 else ""
    technique = sys.argv[3] if len(sys.argv) > 3 else ""

    result = parse_impacket_output(output_path, target, technique)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

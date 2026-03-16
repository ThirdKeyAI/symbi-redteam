#!/usr/bin/env python3
"""
parse-msf.py -- Parse msfconsole text output into structured JSON.

Called by the msf-wrapper.sh script and the parse_msf_output MCP tool.
Takes a msfconsole output file (produced with -o flag) and produces a
structured JSON document suitable for LLM analysis in the ORGA Reason phase.

Msfconsole output is variable-format text. Key patterns to detect:

  [+] lines indicate success (e.g., "[+] 10.0.0.1:445 - Exploit completed")
  [*] lines indicate informational messages
  [-] lines indicate failures
  [!] lines indicate warnings

  Session patterns:
    "session X opened (a.b.c.d:port -> e.f.g.h:port)"
    "Meterpreter session X opened"
    "Command shell session X opened"

Output format:
{
    "module": "exploit/multi/http/apache_struts2_rce",
    "target": "10.0.0.1",
    "payload": "cmd/unix/reverse_bash",
    "success": true,
    "session_type": "shell",
    "sessions": [
        {
            "id": 1,
            "type": "shell",
            "info": "session 1 opened (10.0.0.2:4444 -> 10.0.0.1:52341)"
        }
    ],
    "output_lines": [
        {"level": "+", "text": "Exploit completed successfully"},
        {"level": "*", "text": "Sending stage..."},
        ...
    ]
}
"""

import json
import re
import sys


# Regex patterns for session detection
SESSION_OPENED_PATTERN = re.compile(
    r"session\s+(\d+)\s+opened\s+\(([^)]+)\)",
    re.IGNORECASE,
)

METERPRETER_SESSION_PATTERN = re.compile(
    r"meterpreter\s+session\s+(\d+)\s+opened\s+\(([^)]+)\)",
    re.IGNORECASE,
)

COMMAND_SHELL_SESSION_PATTERN = re.compile(
    r"command\s+shell\s+session\s+(\d+)\s+opened\s+\(([^)]+)\)",
    re.IGNORECASE,
)

# Regex for bracketed status lines: [+], [*], [-], [!]
STATUS_LINE_PATTERN = re.compile(r"^\s*\[([+*\-!])\]\s*(.*)")

# Regex to extract module info from "use" command output
MODULE_PATTERN = re.compile(r"Using configured payload\s+(\S+)", re.IGNORECASE)
USE_MODULE_PATTERN = re.compile(r"^msf\d*\s*(?:exploit|auxiliary|post)\(([^)]+)\)", re.IGNORECASE)


def parse_msf_output(output_path: str) -> dict:
    """Parse msfconsole output into a structured dict."""
    with open(output_path, "r", errors="replace") as f:
        raw_text = f.read()

    lines = raw_text.splitlines()

    sessions = []
    output_lines = []
    success = False
    session_type = "none"
    module = ""
    target = ""
    payload = ""

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # Extract bracketed status lines
        status_match = STATUS_LINE_PATTERN.match(stripped)
        if status_match:
            level = status_match.group(1)
            text = status_match.group(2).strip()
            output_lines.append({"level": level, "text": text})

            # [+] lines indicate success
            if level == "+":
                success = True

        # Detect Meterpreter sessions
        meterpreter_match = METERPRETER_SESSION_PATTERN.search(stripped)
        if meterpreter_match:
            session_id = int(meterpreter_match.group(1))
            session_info = meterpreter_match.group(0)
            sessions.append({
                "id": session_id,
                "type": "meterpreter",
                "info": session_info,
            })
            session_type = "meterpreter"
            success = True
            continue

        # Detect command shell sessions
        shell_match = COMMAND_SHELL_SESSION_PATTERN.search(stripped)
        if shell_match:
            session_id = int(shell_match.group(1))
            session_info = shell_match.group(0)
            sessions.append({
                "id": session_id,
                "type": "shell",
                "info": session_info,
            })
            if session_type == "none":
                session_type = "shell"
            success = True
            continue

        # Detect generic session opened
        session_match = SESSION_OPENED_PATTERN.search(stripped)
        if session_match:
            session_id = int(session_match.group(1))
            session_info = session_match.group(0)

            # Determine type from context
            s_type = "unknown"
            lower_line = stripped.lower()
            if "meterpreter" in lower_line:
                s_type = "meterpreter"
            elif "command shell" in lower_line:
                s_type = "shell"
            elif "vncinject" in lower_line:
                s_type = "vncinject"

            # Avoid duplicate session entries
            existing_ids = {s["id"] for s in sessions}
            if session_id not in existing_ids:
                sessions.append({
                    "id": session_id,
                    "type": s_type,
                    "info": session_info,
                })

            if session_type == "none":
                session_type = s_type
            success = True
            continue

        # Detect payload configuration
        module_match = MODULE_PATTERN.search(stripped)
        if module_match:
            payload = module_match.group(1)

        # Detect RHOSTS setting to extract target
        if "RHOSTS" in stripped.upper() and "=>" in stripped:
            parts = stripped.split("=>")
            if len(parts) >= 2:
                target = parts[-1].strip()

        # Detect explicit failure indicators
        if "[-] Exploit failed" in stripped or "[-] Exploit aborted" in stripped:
            success = False

    # Sort sessions by ID
    sessions.sort(key=lambda s: s["id"])

    # If we found sessions, update session_type from the most recent one
    if sessions:
        session_type = sessions[-1]["type"]

    return {
        "module": module,
        "target": target,
        "payload": payload,
        "success": success,
        "session_type": session_type,
        "sessions": sessions,
        "output_lines": output_lines,
    }


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: parse-msf.py <output_file>"}))
        sys.exit(1)

    output_path = sys.argv[1]

    try:
        result = parse_msf_output(output_path)
        print(json.dumps(result, indent=2))
    except FileNotFoundError:
        print(json.dumps({
            "error": f"File not found: {output_path}",
            "module": "",
            "target": "",
            "payload": "",
            "success": False,
            "session_type": "none",
            "sessions": [],
            "output_lines": [],
        }))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({
            "error": f"Parse error: {e}",
            "module": "",
            "target": "",
            "payload": "",
            "success": False,
            "session_type": "none",
            "sessions": [],
            "output_lines": [],
        }))
        sys.exit(1)


if __name__ == "__main__":
    main()

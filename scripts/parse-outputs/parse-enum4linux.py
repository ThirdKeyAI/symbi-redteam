#!/usr/bin/env python3
"""
parse-enum4linux.py -- Convert enum4linux text output to structured JSON.

Called by the Symbiont runtime after an enum4linux_scan completes. Takes the
enum4linux text output file and produces a JSON document suitable for LLM
analysis in the ORGA Reason phase.

enum4linux produces sectioned text output with headers like:
  =========================================
  |    Target Information    |
  =========================================
  ...
  =========================================
  |    Enumerating Workgroup/Domain on ... |
  =========================================
  ...
  =========================================
  |    Share Enumeration on ... |
  =========================================
  ...

The parser extracts structured data from each section.
"""

import json
import re
import sys
from pathlib import Path


def parse_enum4linux_output(output_path: str) -> dict:
    """Parse enum4linux text output into a structured dict."""
    file_path = Path(output_path)

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    result = {
        "target": extract_target(content),
        "source_file": str(file_path),
        "workgroup": extract_workgroup(content),
        "os_info": extract_os_info(content),
        "shares": extract_shares(content),
        "users": extract_users(content),
        "groups": extract_groups(content),
        "password_policy": extract_password_policy(content),
        "sessions": extract_sessions(content),
        "domain_sid": extract_domain_sid(content),
    }

    return result


def extract_target(content: str) -> str:
    """Extract target IP from enum4linux output."""
    match = re.search(r"Target\s*(?:Information)?.*?:\s*(\S+)", content, re.IGNORECASE)
    if match:
        return match.group(1)

    # Try to find it from the command line or header
    match = re.search(r"enum4linux\s+.*?(\d+\.\d+\.\d+\.\d+)", content)
    if match:
        return match.group(1)

    # Try from "Starting enum4linux" line
    match = re.search(r"on\s+(\d+\.\d+\.\d+\.\d+)", content)
    if match:
        return match.group(1)

    return ""


def extract_workgroup(content: str) -> str:
    """Extract workgroup/domain name."""
    match = re.search(
        r"(?:workgroup|domain).*?:\s*(\S+)", content, re.IGNORECASE
    )
    if match:
        return match.group(1)
    return ""


def extract_os_info(content: str) -> dict:
    """Extract OS information."""
    os_info = {
        "os": "",
        "os_version": "",
        "server_string": "",
        "platform_id": "",
    }

    # Look for OS info patterns
    os_match = re.search(r"OS=\[([^\]]*)\]", content)
    if os_match:
        os_info["os"] = os_match.group(1)

    server_match = re.search(r"Server=\[([^\]]*)\]", content)
    if server_match:
        os_info["server_string"] = server_match.group(1)

    # Samba version
    samba_match = re.search(r"(Samba\s+[\d.]+\S*)", content)
    if samba_match:
        os_info["os_version"] = samba_match.group(1)

    # Platform ID
    platform_match = re.search(r"Platform_id\s*:\s*(\d+)", content)
    if platform_match:
        os_info["platform_id"] = platform_match.group(1)

    return os_info


def extract_shares(content: str) -> list:
    """Extract enumerated SMB shares."""
    shares = []

    # Pattern 1: Share Enumeration table format
    # Sharename       Type      Comment
    # ---------       ----      -------
    # IPC$            IPC       IPC Service
    share_section = extract_section(content, "Share Enumeration")
    if share_section:
        share_pattern = re.compile(
            r"^\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*?)$", re.MULTILINE
        )
        for match in share_pattern.finditer(share_section):
            shares.append({
                "name": match.group(1),
                "type": match.group(2),
                "comment": match.group(3).strip(),
            })

    # Pattern 2: Mapping line format
    # //target/share  Mapping: OK, Listing: OK
    mapping_pattern = re.compile(
        r"//\S+/(\S+)\s+Mapping:\s*(\S+).*?Listing:\s*(\S+)", re.MULTILINE
    )
    share_names = {s["name"] for s in shares}
    for match in mapping_pattern.finditer(content):
        name = match.group(1)
        if name not in share_names:
            shares.append({
                "name": name,
                "type": "Unknown",
                "comment": f"Mapping: {match.group(2)}, Listing: {match.group(3)}",
            })

    return shares


def extract_users(content: str) -> list:
    """Extract enumerated users."""
    users = []
    seen_users = set()

    # Pattern 1: RID cycling results
    # S-1-5-21-...-500 DOMAIN\Administrator (Local User)
    rid_pattern = re.compile(
        r"(S-[\d-]+)\s+\S+\\(\S+)\s+\(([^)]+)\)", re.MULTILINE
    )
    for match in rid_pattern.finditer(content):
        username = match.group(2)
        if username not in seen_users:
            seen_users.add(username)
            users.append({
                "username": username,
                "sid": match.group(1),
                "type": match.group(3),
            })

    # Pattern 2: Users enumeration via SAMR
    # user:[username] rid:[0x1f4]
    samr_pattern = re.compile(
        r"user:\[([^\]]+)\]\s+rid:\[([^\]]+)\]", re.MULTILINE
    )
    for match in samr_pattern.finditer(content):
        username = match.group(1)
        if username not in seen_users:
            seen_users.add(username)
            users.append({
                "username": username,
                "sid": "",
                "type": f"rid={match.group(2)}",
            })

    return users


def extract_groups(content: str) -> list:
    """Extract enumerated groups."""
    groups = []
    seen_groups = set()

    # Pattern: group:[groupname] rid:[0x201]
    group_pattern = re.compile(
        r"group:\[([^\]]+)\]\s+rid:\[([^\]]+)\]", re.MULTILINE
    )
    for match in group_pattern.finditer(content):
        group_name = match.group(1)
        if group_name not in seen_groups:
            seen_groups.add(group_name)
            groups.append({
                "name": group_name,
                "rid": match.group(2),
            })

    return groups


def extract_password_policy(content: str) -> dict:
    """Extract password policy information."""
    policy = {}

    policy_section = extract_section(content, "Password Policy")
    if not policy_section:
        # Try alternate section name
        policy_section = extract_section(content, "Password Info")

    search_content = policy_section if policy_section else content

    patterns = {
        "min_length": r"[Mm]inimum\s+[Pp]assword\s+[Ll]ength:\s*(\d+)",
        "password_history": r"[Pp]assword\s+[Hh]istory\s+[Ll]ength:\s*(\d+)",
        "max_password_age": r"[Mm]aximum\s+[Pp]assword\s+[Aa]ge.*?:\s*(.*?)$",
        "min_password_age": r"[Mm]inimum\s+[Pp]assword\s+[Aa]ge.*?:\s*(.*?)$",
        "lockout_threshold": r"[Ll]ockout\s+[Tt]hreshold:\s*(\d+)",
        "lockout_duration": r"[Ll]ockout\s+[Dd]uration.*?:\s*(.*?)$",
        "lockout_observation_window": r"[Ll]ockout\s+[Oo]bservation\s+[Ww]indow.*?:\s*(.*?)$",
        "complexity": r"[Pp]assword\s+[Cc]omplexity.*?:\s*(.*?)$",
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, search_content, re.MULTILINE)
        if match:
            value = match.group(1).strip()
            # Try to convert numeric values
            try:
                policy[key] = int(value)
            except ValueError:
                policy[key] = value

    return policy


def extract_sessions(content: str) -> list:
    """Extract session/connection information."""
    sessions = []

    # Pattern: session established with null credentials
    if re.search(r"[Nn]ull\s+[Ss]ession", content, re.IGNORECASE):
        sessions.append({
            "type": "null_session",
            "status": "established",
        })

    # Pattern: Anonymous session
    if re.search(r"[Aa]nonymous.*(?:allowed|success)", content, re.IGNORECASE):
        sessions.append({
            "type": "anonymous",
            "status": "allowed",
        })

    return sessions


def extract_domain_sid(content: str) -> str:
    """Extract the domain SID."""
    match = re.search(r"Domain\s+Sid:\s*(S-[\d-]+)", content)
    if match:
        return match.group(1)
    return ""


def extract_section(content: str, section_name: str) -> str:
    """Extract content between section headers.

    enum4linux uses headers like:
     =========================================
     |    Section Name on target    |
     =========================================
    """
    # Build pattern to match section header and capture until next section
    pattern = re.compile(
        r"={3,}\s*\n"
        r"\|\s*" + re.escape(section_name) + r".*?\|\s*\n"
        r"={3,}\s*\n"
        r"(.*?)"
        r"(?:={3,}\s*\n|\Z)",
        re.DOTALL | re.IGNORECASE,
    )
    match = pattern.search(content)
    if match:
        return match.group(1)
    return ""


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: parse-enum4linux.py <output_file>"}))
        sys.exit(1)

    output_path = sys.argv[1]

    try:
        result = parse_enum4linux_output(output_path)
        print(json.dumps(result, indent=2))
    except FileNotFoundError:
        print(json.dumps({"error": f"File not found: {output_path}"}))
        sys.exit(1)
    except PermissionError:
        print(json.dumps({"error": f"Permission denied: {output_path}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()

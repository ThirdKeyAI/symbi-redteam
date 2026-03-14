#!/usr/bin/env python3
"""
parse-nmap-xml.py -- Convert nmap XML output to structured JSON.

Called by the parse_nmap_xml MCP tool. Takes an nmap XML file and produces
a JSON document suitable for LLM analysis in the ORGA Reason phase.

The parser extracts:
  - Host states and addresses
  - Open ports with service/version info
  - OS detection results (when available)
  - Script output (when available)
  - Scan metadata (timing, command, stats)
"""

import json
import sys
from lxml import etree


def parse_nmap_xml(xml_path: str) -> dict:
    """Parse nmap XML output into a structured dict."""
    tree = etree.parse(xml_path)
    root = tree.getroot()

    # Scan metadata
    scan_info = {
        "scanner": root.get("scanner", "nmap"),
        "args": root.get("args", ""),
        "start_time": root.get("startstr", ""),
        "version": root.get("version", ""),
    }

    # Parse run stats
    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        hosts_elem = runstats.find("hosts")
        scan_info["end_time"] = finished.get("timestr", "") if finished is not None else ""
        scan_info["elapsed_seconds"] = float(finished.get("elapsed", 0)) if finished is not None else 0
        if hosts_elem is not None:
            scan_info["hosts_up"] = int(hosts_elem.get("up", 0))
            scan_info["hosts_down"] = int(hosts_elem.get("down", 0))
            scan_info["hosts_total"] = int(hosts_elem.get("total", 0))

    # Parse hosts
    hosts = []
    for host_elem in root.findall("host"):
        host = parse_host(host_elem)
        if host:
            hosts.append(host)

    return {
        "scan_info": scan_info,
        "hosts_count": len(hosts),
        "hosts": hosts,
    }


def parse_host(host_elem) -> dict:
    """Parse a single host element."""
    host = {
        "state": "",
        "ip": "",
        "hostname": "",
        "mac": "",
        "vendor": "",
        "ports": [],
        "os_guesses": [],
        "scripts": [],
    }

    # Host state
    status = host_elem.find("status")
    if status is not None:
        host["state"] = status.get("state", "unknown")

    # Addresses
    for addr in host_elem.findall("address"):
        addr_type = addr.get("addrtype", "")
        if addr_type == "ipv4":
            host["ip"] = addr.get("addr", "")
        elif addr_type == "mac":
            host["mac"] = addr.get("addr", "")
            host["vendor"] = addr.get("vendor", "")

    # Hostnames
    hostnames = host_elem.find("hostnames")
    if hostnames is not None:
        hostname_elem = hostnames.find("hostname")
        if hostname_elem is not None:
            host["hostname"] = hostname_elem.get("name", "")

    # Ports
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            port = parse_port(port_elem)
            if port:
                host["ports"].append(port)

    # OS detection
    os_elem = host_elem.find("os")
    if os_elem is not None:
        for osmatch in os_elem.findall("osmatch"):
            host["os_guesses"].append({
                "name": osmatch.get("name", ""),
                "accuracy": int(osmatch.get("accuracy", 0)),
            })

    # Host scripts
    hostscript = host_elem.find("hostscript")
    if hostscript is not None:
        for script in hostscript.findall("script"):
            host["scripts"].append({
                "id": script.get("id", ""),
                "output": script.get("output", ""),
            })

    return host


def parse_port(port_elem) -> dict:
    """Parse a single port element."""
    port = {
        "port": int(port_elem.get("portid", 0)),
        "protocol": port_elem.get("protocol", "tcp"),
        "state": "",
        "reason": "",
        "service": "",
        "version": "",
        "product": "",
        "extra_info": "",
        "scripts": [],
    }

    # Port state
    state_elem = port_elem.find("state")
    if state_elem is not None:
        port["state"] = state_elem.get("state", "")
        port["reason"] = state_elem.get("reason", "")

    # Service info
    service_elem = port_elem.find("service")
    if service_elem is not None:
        port["service"] = service_elem.get("name", "")
        port["product"] = service_elem.get("product", "")
        port["version"] = service_elem.get("version", "")
        port["extra_info"] = service_elem.get("extrainfo", "")

    # Port scripts (vuln detection, etc.)
    for script in port_elem.findall("script"):
        port["scripts"].append({
            "id": script.get("id", ""),
            "output": script.get("output", ""),
        })

    return port


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: parse-nmap-xml.py <xml_file>"}))
        sys.exit(1)

    xml_path = sys.argv[1]

    try:
        result = parse_nmap_xml(xml_path)
        print(json.dumps(result, indent=2))
    except etree.XMLSyntaxError as e:
        print(json.dumps({"error": f"XML parse error: {e}"}))
        sys.exit(1)
    except FileNotFoundError:
        print(json.dumps({"error": f"File not found: {xml_path}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()

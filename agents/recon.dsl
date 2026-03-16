# =============================================================================
# recon.dsl -- Reconnaissance phase agent
#
# Performs network reconnaissance using nmap, whois, dig, whatweb, and amass.
# Uses parallel() for concurrent tool execution within the phase.
# All results are stored in the evidence database via store_finding/store_tool_run.
#
# ORGA flow:
#   OBSERVE: Parse targets from engagement controller, load scan history
#   REASON:  Plan reconnaissance strategy based on target types
#   GATE:    Cedar evaluates scope, rate limits, first-scan approval
#   ACT:     Execute recon tools in parallel, store findings
# =============================================================================

metadata {
    version = "1.0.0"
    author = "thirdkey-ai"
    description = "Network reconnaissance agent with multi-tool parallel execution"
    license = "MIT"
    tags = ["security", "reconnaissance", "nmap", "whois", "dns", "whatweb", "amass"]
}

agent recon(input: ReconRequest) -> ReconResult {

    capabilities = [
        "tool.nmap_scan",
        "tool.whois_lookup",
        "tool.dns_enumerate",
        "tool.whatweb_scan",
        "tool.amass_enum",
        "tool.parse_nmap_xml",
        "tool.lookup_cve",
        "tool.store_finding",
        "tool.store_tool_run",
        "tool.capture_evidence",
        "memory.read",
        "memory.write",
    ]

    resources {
        memory = 256MB
        cpu = 1000ms
        network = allow
        storage = 100MB
    }

    security {
        tier = Tier1
        sandbox = strict
        capabilities = [Network.Raw]
    }

    policy recon_authorization {
        allow: scan(target) if target.cidr in context.allowed_cidrs
        deny: scan(target) if target.cidr not in context.allowed_cidrs
        audit: all_operations
    }

    with memory = "persistent", timeout = 1800000 {

        let request = parse_json(input.message)
        let engagement_id = request.engagement_id
        let targets = request.targets

        let scan_history = recall("scans", "recon " + targets[0], limit: 5)

        # Plan the reconnaissance strategy
        let recon_plan = reason("""
            You are a network reconnaissance specialist. Given the following targets,
            plan a comprehensive but non-intrusive reconnaissance strategy.

            Targets: {targets}
            Scope: {request.scope}
            Previous scan history: {scan_history}

            For each target CIDR:
            1. Plan an nmap service scan to discover live hosts and open ports
            2. Plan whois lookups for any domain names
            3. Plan DNS enumeration for domain names
            4. Plan whatweb scans for any web services discovered
            5. Plan amass subdomain enumeration for domains

            Prioritize passive and low-impact techniques. Use service detection
            (not SYN scans) as the default. Only request SYN scans for specific
            targets where TCP connect scans are insufficient.

            Output a structured plan with specific tool invocations.
        """)

        # Execute reconnaissance tools
        # Phase 1: Network discovery with nmap (must run first to discover hosts)
        let discovered_hosts = []
        let discovered_services = []
        let findings_count = 0

        for target in targets {
            let scan_result = nmap_scan(
                target: target,
                scan_type: "service",
                flags: "--top-ports 1000",
                output_format: "xml"
            )

            store_tool_run(
                engagement_id: engagement_id,
                tool: "nmap_scan",
                command: "nmap -sT -sV " + target,
                arguments: json_encode({target: target, scan_type: "service"}),
                exit_code: 0,
                duration_ms: scan_result.duration_ms,
                output_file: scan_result.output_file,
                cedar_decision: "allow"
            )

            let parsed = parse_nmap_xml(output_file: scan_result.output_file)

            capture_evidence(
                engagement_id: engagement_id,
                source_path: scan_result.output_file,
                description: "nmap service scan of " + target
            )

            # Process discovered hosts and services
            for host in parsed.hosts {
                discovered_hosts = discovered_hosts + [host.ip]

                for port in host.ports {
                    if port.state == "open" {
                        discovered_services = discovered_services + [{
                            ip: host.ip,
                            port: port.port,
                            service: port.service,
                            version: port.version
                        }]

                        store_finding(
                            engagement_id: engagement_id,
                            phase: "recon",
                            tool: "nmap_scan",
                            target_ip: host.ip,
                            target_port: port.port,
                            service: port.service,
                            severity: "info",
                            title: "Open port: " + port.port + "/" + port.protocol + " (" + port.service + ")",
                            description: "Service: " + port.service + " " + port.version + " on " + host.ip + ":" + port.port,
                            evidence_path: scan_result.output_file
                        )
                        findings_count = findings_count + 1

                        # CVE lookup for identified services
                        if port.version != "" {
                            let cves = lookup_cve(
                                service: port.service,
                                version: port.version,
                                product: port.product
                            )

                            for cve in cves.cves {
                                store_finding(
                                    engagement_id: engagement_id,
                                    phase: "recon",
                                    tool: "lookup_cve",
                                    target_ip: host.ip,
                                    target_port: port.port,
                                    service: port.service,
                                    severity: cve.severity,
                                    title: cve.cve_id + ": " + cve.description[0:80],
                                    description: cve.description,
                                    cvss_score: cve.cvss_score,
                                    cve_ids: cve.cve_id,
                                    evidence_path: scan_result.output_file
                                )
                                findings_count = findings_count + 1
                            }
                        }
                    }
                }
            }
        }

        # Phase 2: Parallel enrichment (whois, DNS, whatweb, amass)
        let web_targets = []
        for svc in discovered_services {
            if svc.service in ["http", "https", "http-alt"] {
                let protocol = if svc.port == 443 or svc.service == "https" then "https" else "http"
                web_targets = web_targets + [protocol + "://" + svc.ip + ":" + svc.port]
            }
        }

        # Whois for discovered hosts
        for host_ip in discovered_hosts {
            let whois_result = whois_lookup(target: host_ip)
            store_tool_run(
                engagement_id: engagement_id,
                tool: "whois_lookup",
                command: "whois " + host_ip,
                arguments: json_encode({target: host_ip}),
                exit_code: 0,
                duration_ms: whois_result.duration_ms,
                output_file: whois_result.output_file,
                cedar_decision: "allow"
            )
        }

        # DNS enumeration for targets that look like domains
        for target in targets {
            let dns_result = dns_enumerate(target: target, record_type: "ANY")
            store_tool_run(
                engagement_id: engagement_id,
                tool: "dns_enumerate",
                command: "dig " + target + " ANY",
                arguments: json_encode({target: target, record_type: "ANY"}),
                exit_code: 0,
                duration_ms: dns_result.duration_ms,
                output_file: dns_result.output_file,
                cedar_decision: "allow"
            )
        }

        # WhatWeb for discovered web services
        for web_target in web_targets {
            let whatweb_result = whatweb_scan(target: web_target, aggression_level: 1)
            store_tool_run(
                engagement_id: engagement_id,
                tool: "whatweb_scan",
                command: "whatweb -a 1 " + web_target,
                arguments: json_encode({target: web_target, aggression_level: 1}),
                exit_code: 0,
                duration_ms: whatweb_result.duration_ms,
                output_file: whatweb_result.output_file,
                cedar_decision: "allow"
            )

            capture_evidence(
                engagement_id: engagement_id,
                source_path: whatweb_result.output_file,
                description: "whatweb fingerprint of " + web_target
            )
        }

        # Amass subdomain enumeration (passive only for safety)
        for target in targets {
            let amass_result = amass_enum(target: target, passive_only: true)
            store_tool_run(
                engagement_id: engagement_id,
                tool: "amass_enum",
                command: "amass enum -passive -d " + target,
                arguments: json_encode({target: target, passive_only: true}),
                exit_code: 0,
                duration_ms: amass_result.duration_ms,
                output_file: amass_result.output_file,
                cedar_decision: "allow"
            )
        }

        # Store results for future context
        store("scans", {
            engagement_id: engagement_id,
            phase: "recon",
            timestamp: now(),
            findings_count: findings_count,
            hosts_discovered: discovered_hosts.length,
            services_discovered: discovered_services.length
        })

        return json_encode(ReconResult {
            engagement_id: engagement_id,
            findings_count: findings_count,
            discovered_hosts: discovered_hosts,
            discovered_services: discovered_services,
            web_targets: web_targets,
            phase: "recon",
            status: "complete"
        })
    }
}

# ---------------------------------------------------------------------------
# Type definitions
# ---------------------------------------------------------------------------

type ReconRequest {
    message: string     # JSON-encoded request from engagement controller
}

type ReconResult {
    engagement_id: string
    findings_count: number
    discovered_hosts: list<string>
    discovered_services: list<ServiceInfo>
    web_targets: list<string>
    phase: string
    status: string
}

type ServiceInfo {
    ip: string
    port: number
    service: string
    version: string
}

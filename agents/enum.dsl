// =============================================================================
// enum.dsl -- Enumeration phase agent
//
// Performs service enumeration using nikto, gobuster, enum4linux, smbclient,
// and snmpwalk. Targets are derived from recon phase findings.
// =============================================================================

metadata {
    version = "1.0.0"
    author = "thirdkey-ai"
    description = "Service enumeration agent for web, SMB, and SNMP targets"
    license = "Apache-2.0"
    tags = ["security", "enumeration", "nikto", "gobuster", "smb", "snmp"]
}

agent enum(input: EnumRequest) -> EnumResult {

    capabilities = [
        "tool.nikto_scan",
        "tool.gobuster_scan",
        "tool.enum4linux_scan",
        "tool.smbclient_access",
        "tool.snmpwalk_enum",
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

    policy enum_authorization {
        allow: enumerate(target) if context.phase_status.recon_findings_count >= 1
        deny: enumerate(target) if context.phase_status.recon_findings_count < 1
        audit: all_operations
    }

    with memory = "persistent", timeout = 1800000 {

        let request = parse_json(input.message)
        let engagement_id = request.engagement_id
        let targets = request.targets
        let services = request.services
        let findings_count = 0
        let enumerated_targets = []
        let web_applications = []
        let discovered_services = []
        let discovered_credentials = []

        let enum_plan = reason("""
            You are a penetration test enumeration specialist. Given the discovered
            hosts and services from reconnaissance, plan targeted enumeration.

            Hosts: {targets}
            Services: {services}
            Scope: {request.scope}

            For each discovered service, determine the appropriate enumeration tool:
            - HTTP/HTTPS services → nikto (vulnerability scan) + gobuster (directory brute force)
            - SMB services (port 445/139) → enum4linux + smbclient
            - SNMP services (port 161) → snmpwalk
            - Other services → note for manual follow-up

            Prioritize web application enumeration as it typically yields the most findings.
            Use conservative wordlists and settings to avoid detection.
        """)

        // Enumerate web services with nikto and gobuster
        for svc in services {
            if svc.service in ["http", "https", "http-alt", "http-proxy"] {
                let protocol = if svc.port == 443 or svc.service == "https" then "https" else "http"
                let web_url = protocol + "://" + svc.ip + ":" + svc.port

                // Nikto scan
                let nikto_result = nikto_scan(target: web_url, tuning: 0)
                store_tool_run(
                    engagement_id: engagement_id,
                    tool: "nikto_scan",
                    command: "nikto -h " + web_url,
                    arguments: json_encode({target: web_url}),
                    exit_code: 0,
                    duration_ms: nikto_result.duration_ms,
                    output_file: nikto_result.output_file,
                    cedar_decision: "allow"
                )

                capture_evidence(
                    engagement_id: engagement_id,
                    source_path: nikto_result.output_file,
                    description: "nikto scan of " + web_url
                )

                // Parse nikto findings
                if nikto_result.findings_count > 0 {
                    for finding in nikto_result.findings {
                        store_finding(
                            engagement_id: engagement_id,
                            phase: "enum",
                            tool: "nikto_scan",
                            target_ip: svc.ip,
                            target_port: svc.port,
                            service: svc.service,
                            severity: classify_nikto_severity(finding),
                            title: finding.msg,
                            description: "Method: " + finding.method + " URL: " + finding.url,
                            evidence_path: nikto_result.output_file
                        )
                        findings_count = findings_count + 1
                    }
                }

                // Gobuster directory brute force
                let gobuster_result = gobuster_scan(
                    target: web_url,
                    mode: "dir",
                    wordlist: "/usr/share/seclists/Discovery/Web-Content/common.txt",
                    extensions: "php,html,txt,asp,aspx,jsp"
                )
                store_tool_run(
                    engagement_id: engagement_id,
                    tool: "gobuster_scan",
                    command: "gobuster dir -u " + web_url + " -w common.txt",
                    arguments: json_encode({target: web_url, mode: "dir"}),
                    exit_code: 0,
                    duration_ms: gobuster_result.duration_ms,
                    output_file: gobuster_result.output_file,
                    cedar_decision: "allow"
                )

                capture_evidence(
                    engagement_id: engagement_id,
                    source_path: gobuster_result.output_file,
                    description: "gobuster dir scan of " + web_url
                )

                for entry in gobuster_result.entries {
                    let severity = if entry.status == 200 then "info"
                                   else if entry.status == 403 then "low"
                                   else if entry.status == 500 then "medium"
                                   else "info"
                    store_finding(
                        engagement_id: engagement_id,
                        phase: "enum",
                        tool: "gobuster_scan",
                        target_ip: svc.ip,
                        target_port: svc.port,
                        service: svc.service,
                        severity: severity,
                        title: "Discovered path: " + entry.path + " (HTTP " + entry.status + ")",
                        description: "Path: " + entry.path + " Status: " + entry.status + " Size: " + entry.size,
                        evidence_path: gobuster_result.output_file
                    )
                    findings_count = findings_count + 1
                }

                web_applications = web_applications + [web_url]
                enumerated_targets = enumerated_targets + [svc.ip]
            }

            // Enumerate SMB services
            if svc.service in ["microsoft-ds", "netbios-ssn", "smb"] or svc.port in [445, 139] {
                let e4l_result = enum4linux_scan(target: svc.ip, options: "-a")
                store_tool_run(
                    engagement_id: engagement_id,
                    tool: "enum4linux_scan",
                    command: "enum4linux -a " + svc.ip,
                    arguments: json_encode({target: svc.ip, options: "-a"}),
                    exit_code: 0,
                    duration_ms: e4l_result.duration_ms,
                    output_file: e4l_result.output_file,
                    cedar_decision: "allow"
                )

                capture_evidence(
                    engagement_id: engagement_id,
                    source_path: e4l_result.output_file,
                    description: "enum4linux scan of " + svc.ip
                )

                if e4l_result.shares.length > 0 {
                    for share in e4l_result.shares {
                        store_finding(
                            engagement_id: engagement_id,
                            phase: "enum",
                            tool: "enum4linux_scan",
                            target_ip: svc.ip,
                            target_port: svc.port,
                            service: "smb",
                            severity: if share.access == "READ" or share.access == "READ,WRITE" then "medium" else "info",
                            title: "SMB share discovered: " + share.name,
                            description: "Share: " + share.name + " Type: " + share.type + " Access: " + share.access,
                            evidence_path: e4l_result.output_file
                        )
                        findings_count = findings_count + 1
                    }
                }

                // Try anonymous SMB access
                let smb_result = smbclient_access(target: svc.ip)
                store_tool_run(
                    engagement_id: engagement_id,
                    tool: "smbclient_access",
                    command: "smbclient -L //" + svc.ip + " -N",
                    arguments: json_encode({target: svc.ip}),
                    exit_code: 0,
                    duration_ms: smb_result.duration_ms,
                    output_file: smb_result.output_file,
                    cedar_decision: "allow"
                )

                enumerated_targets = enumerated_targets + [svc.ip]
            }

            // Enumerate SNMP services
            if svc.service == "snmp" or svc.port == 161 {
                let snmp_result = snmpwalk_enum(
                    target: svc.ip,
                    community: "public",
                    version: "2c"
                )
                store_tool_run(
                    engagement_id: engagement_id,
                    tool: "snmpwalk_enum",
                    command: "snmpwalk -v2c -c public " + svc.ip,
                    arguments: json_encode({target: svc.ip, community: "public"}),
                    exit_code: 0,
                    duration_ms: snmp_result.duration_ms,
                    output_file: snmp_result.output_file,
                    cedar_decision: "allow"
                )

                if snmp_result.status == "success" {
                    store_finding(
                        engagement_id: engagement_id,
                        phase: "enum",
                        tool: "snmpwalk_enum",
                        target_ip: svc.ip,
                        target_port: 161,
                        service: "snmp",
                        severity: "medium",
                        title: "SNMP community string 'public' accepted",
                        description: "Default SNMP community string allows information disclosure",
                        remediation: "Change default SNMP community strings and restrict SNMP access",
                        evidence_path: snmp_result.output_file
                    )
                    findings_count = findings_count + 1
                }

                enumerated_targets = enumerated_targets + [svc.ip]
            }
        }

        store("scans", {
            engagement_id: engagement_id,
            phase: "enum",
            timestamp: now(),
            findings_count: findings_count,
            targets_enumerated: enumerated_targets.length,
            web_apps_found: web_applications.length
        })

        return json_encode(EnumResult {
            engagement_id: engagement_id,
            findings_count: findings_count,
            enumerated_targets: enumerated_targets,
            discovered_services: discovered_services,
            web_applications: web_applications,
            discovered_credentials: discovered_credentials,
            phase: "enum",
            status: "complete"
        })
    }
}

type EnumRequest {
    message: string
}

type EnumResult {
    engagement_id: string
    findings_count: number
    enumerated_targets: list<string>
    discovered_services: list<ServiceInfo>
    web_applications: list<string>
    discovered_credentials: list<CredentialInfo>
    phase: string
    status: string
}

type ServiceInfo {
    ip: string
    port: number
    service: string
    version: string
}

type CredentialInfo {
    target: string
    username: string
    password: string
    service: string
    source: string
}

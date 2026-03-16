# =============================================================================
# vuln-assess.dsl -- Vulnerability assessment phase agent
#
# Performs vulnerability scanning using nmap NSE scripts, nuclei templates,
# sqlmap detection, and searchsploit queries. Non-production targets only.
# =============================================================================

metadata {
    version = "1.0.0"
    author = "thirdkey-ai"
    description = "Vulnerability assessment agent with template-based scanning"
    license = "MIT"
    tags = ["security", "vulnerability", "nuclei", "sqlmap", "nse"]
}

agent vuln_assess(input: VulnRequest) -> VulnResult {

    capabilities = [
        "tool.nmap_vuln_script",
        "tool.nuclei_scan",
        "tool.sqlmap_detect",
        "tool.searchsploit_query",
        "tool.store_finding",
        "tool.store_tool_run",
        "tool.capture_evidence",
        "memory.read",
        "memory.write",
    ]

    resources {
        memory = 512MB
        cpu = 2000ms
        network = allow
        storage = 200MB
    }

    security {
        tier = Tier1
        sandbox = strict
        capabilities = [Network.Raw]
    }

    policy vuln_authorization {
        allow: assess(target) if context.phase_status.enum_complete == true
        deny: assess(target) if target.environment == "production"
        audit: all_operations
    }

    with memory = "persistent", timeout = 1800000 {

        let request = parse_json(input.message)
        let engagement_id = request.engagement_id
        let targets = request.targets
        let services = request.services
        let web_apps = request.web_apps
        let findings_count = 0
        let exploitable_findings = []
        let vulnerable_targets = []
        let exploitable_count = 0

        let vuln_plan = reason("""
            You are a vulnerability assessment specialist. Given the enumerated
            targets and services, plan a comprehensive vulnerability assessment.

            Targets: {targets}
            Services: {services}
            Web Applications: {web_apps}
            Scope: {request.scope}

            Strategy:
            1. Run nmap NSE vulnerability scripts against all hosts with open ports
            2. Run nuclei with critical+high severity templates against web apps
            3. Run sqlmap detection against web app parameters
            4. Search searchsploit for known exploits for discovered service versions

            Focus on findings that are exploitable. Prioritize web applications
            and services with known CVEs from the recon phase.
        """)

        # NSE vulnerability scripts against discovered hosts
        for target in targets {
            let nmap_vuln = nmap_vuln_script(
                target: target,
                port_range: "1-10000",
                scripts: "vuln"
            )
            store_tool_run(
                engagement_id: engagement_id,
                tool: "nmap_vuln_script",
                command: "nmap -sV --script=vuln " + target,
                arguments: json_encode({target: target, scripts: "vuln"}),
                exit_code: 0,
                duration_ms: nmap_vuln.duration_ms,
                output_file: nmap_vuln.output_file,
                cedar_decision: "allow"
            )

            capture_evidence(
                engagement_id: engagement_id,
                source_path: nmap_vuln.output_file,
                description: "nmap vuln scripts against " + target
            )

            for vuln in nmap_vuln.vulnerabilities {
                store_finding(
                    engagement_id: engagement_id,
                    phase: "vuln",
                    tool: "nmap_vuln_script",
                    target_ip: vuln.host,
                    target_port: vuln.port,
                    service: vuln.service,
                    severity: vuln.severity,
                    title: vuln.title,
                    description: vuln.description,
                    cve_ids: vuln.cve_ids,
                    cvss_score: vuln.cvss_score,
                    remediation: vuln.remediation,
                    evidence_path: nmap_vuln.output_file
                )
                findings_count = findings_count + 1

                if vuln.severity in ["critical", "high"] {
                    exploitable_findings = exploitable_findings + [vuln]
                    exploitable_count = exploitable_count + 1
                    if vuln.host not in vulnerable_targets {
                        vulnerable_targets = vulnerable_targets + [vuln.host]
                    }
                }
            }
        }

        # Nuclei template scanning against web applications
        for web_app in web_apps {
            let nuclei_result = nuclei_scan(
                target: web_app,
                severity_filter: "critical,high,medium",
                rate_limit: 150
            )
            store_tool_run(
                engagement_id: engagement_id,
                tool: "nuclei_scan",
                command: "nuclei -u " + web_app + " -severity critical,high,medium",
                arguments: json_encode({target: web_app, severity_filter: "critical,high,medium"}),
                exit_code: 0,
                duration_ms: nuclei_result.duration_ms,
                output_file: nuclei_result.output_file,
                cedar_decision: "allow"
            )

            capture_evidence(
                engagement_id: engagement_id,
                source_path: nuclei_result.output_file,
                description: "nuclei scan of " + web_app
            )

            for finding in nuclei_result.findings {
                store_finding(
                    engagement_id: engagement_id,
                    phase: "vuln",
                    tool: "nuclei_scan",
                    target_ip: finding.host,
                    target_port: finding.port,
                    service: "http",
                    severity: finding.severity,
                    title: finding.template_id + ": " + finding.name,
                    description: finding.description,
                    cve_ids: finding.cve_ids,
                    remediation: finding.remediation,
                    evidence_path: nuclei_result.output_file
                )
                findings_count = findings_count + 1

                if finding.severity in ["critical", "high"] {
                    exploitable_findings = exploitable_findings + [finding]
                    exploitable_count = exploitable_count + 1
                }
            }
        }

        # SQLMap detection against web application parameters
        for web_app in web_apps {
            let sqlmap_result = sqlmap_detect(
                target_url: web_app,
                method: "GET",
                level: 1,
                risk: 1
            )
            store_tool_run(
                engagement_id: engagement_id,
                tool: "sqlmap_detect",
                command: "sqlmap -u " + web_app + " --batch --level=1 --risk=1",
                arguments: json_encode({target_url: web_app, method: "GET", level: 1, risk: 1}),
                exit_code: 0,
                duration_ms: sqlmap_result.duration_ms,
                output_file: sqlmap_result.output_file,
                cedar_decision: "allow"
            )

            if sqlmap_result.vulnerable {
                for injection in sqlmap_result.injection_points {
                    store_finding(
                        engagement_id: engagement_id,
                        phase: "vuln",
                        tool: "sqlmap_detect",
                        target_ip: web_app,
                        service: "http",
                        severity: "critical",
                        title: "SQL Injection: " + injection.parameter + " (" + injection.type + ")",
                        description: "Injection type: " + injection.type + " Title: " + injection.title + " Payload: " + injection.payload,
                        remediation: "Use parameterized queries. Implement input validation.",
                        evidence_path: sqlmap_result.output_file
                    )
                    findings_count = findings_count + 1
                    exploitable_count = exploitable_count + 1
                    exploitable_findings = exploitable_findings + [injection]
                }
            }
        }

        # Searchsploit for discovered service versions
        for svc in services {
            if svc.version != "" {
                let search_query = svc.service + " " + svc.version
                let sploit_result = searchsploit_query(
                    query: search_query,
                    exact: false
                )
                store_tool_run(
                    engagement_id: engagement_id,
                    tool: "searchsploit_query",
                    command: "searchsploit " + search_query,
                    arguments: json_encode({query: search_query}),
                    exit_code: 0,
                    duration_ms: sploit_result.duration_ms,
                    cedar_decision: "allow"
                )

                for exploit in sploit_result.exploits {
                    store_finding(
                        engagement_id: engagement_id,
                        phase: "vuln",
                        tool: "searchsploit_query",
                        target_ip: svc.ip,
                        target_port: svc.port,
                        service: svc.service,
                        severity: "medium",
                        title: "Known exploit: " + exploit.title,
                        description: "Exploit DB: " + exploit.path + " Type: " + exploit.type + " Platform: " + exploit.platform,
                        evidence_path: exploit.path
                    )
                    findings_count = findings_count + 1
                }
            }
        }

        store("scans", {
            engagement_id: engagement_id,
            phase: "vuln",
            timestamp: now(),
            findings_count: findings_count,
            exploitable_count: exploitable_count
        })

        return json_encode(VulnResult {
            engagement_id: engagement_id,
            findings_count: findings_count,
            exploitable_count: exploitable_count,
            exploitable_findings: exploitable_findings,
            vulnerable_targets: vulnerable_targets,
            phase: "vuln",
            status: "complete"
        })
    }
}

type VulnRequest {
    message: string
}

type VulnResult {
    engagement_id: string
    findings_count: number
    exploitable_count: number
    exploitable_findings: list<VulnFinding>
    vulnerable_targets: list<string>
    phase: string
    status: string
}

type VulnFinding {
    host: string
    port: number
    service: string
    severity: string
    title: string
    description: string
    cve_ids: string
}

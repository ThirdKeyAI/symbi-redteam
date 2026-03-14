# =============================================================================
# nmap-recon.dsl -- Governed network reconnaissance agent
#
# This agent wraps nmap with AI reasoning and Cedar policy enforcement.
# The ORGA loop ensures every scan is authorized, proportionate, and audited.
#
# ORGA flow for a scan request:
#   OBSERVE: Parse request, load target context, check scan history
#   REASON:  Select scan type, build nmap command, assess risk
#   GATE:    Cedar evaluates target authorization, scan type, rate limits
#   ACT:     Execute approved nmap command in sandbox, collect results
#   (loop back to OBSERVE for result interpretation)
# =============================================================================

metadata {
    version: "1.0.0"
    author: "thirdkey-ai"
    description: "AI-governed network reconnaissance with nmap"
    license: "MIT"
    tags: ["security", "reconnaissance", "nmap", "network"]
}

# ---------------------------------------------------------------------------
# Agent definition
# ---------------------------------------------------------------------------

agent nmap_recon(input: ScanRequest) -> ScanReport {

    # Capabilities this agent is allowed to use.
    # The runtime enforces this -- the LLM cannot invoke unlisted capabilities.
    capabilities: [
        "tool.nmap_scan",           # Execute nmap via the sandboxed wrapper
        "tool.parse_nmap_xml",      # Parse nmap XML output
        "tool.lookup_cve",          # Cross-reference CVE databases
        "memory.read",              # Read scan history from vector store
        "memory.write",             # Store scan results for future context
    ]

    # Resource constraints
    resources {
        memory: 256MB
        cpu: 1000ms
        network: allow              # Agent needs network for scanning
        storage: 50MB               # For scan output and reports
    }

    # Sandbox configuration
    security {
        tier: Tier1                 # Docker isolation
        sandbox: strict             # Read-only root, dropped caps
        capabilities: [Network.Raw] # nmap needs CAP_NET_RAW
    }

    # ---------------------------------------------------------------------------
    # Policy blocks -- evaluated at the ORGA Gate phase
    # These are inline policy hints; the authoritative policies live in
    # policies/*.cedar and are evaluated by the Cedar engine.
    # ---------------------------------------------------------------------------

    policy target_authorization {
        # Only scan targets in explicitly allowed CIDR ranges
        allow: scan(target) if target.cidr in context.allowed_cidrs
        deny: scan(target) if target.cidr not in context.allowed_cidrs
        audit: all_operations
    }

    policy scan_type_governance {
        # Service detection and version scans are always allowed
        allow: scan(target) if scan_type in ["service", "version", "ping"]

        # SYN scans require the target to be in a non-production environment
        allow: scan(target) if scan_type == "syn" and target.environment != "production"

        # OS fingerprinting and aggressive scans require human approval
        require: human_approval if scan_type in ["os_detect", "aggressive", "vuln_script"]

        # Never allow these
        deny: scan(target) if scan_type in ["exploit", "brute_force"]
    }

    policy rate_limits {
        # Max 10 scans per hour per target CIDR
        deny: scan(target) if rate_count("scan", target.cidr, "1h") > 10

        # Max 100 scans per hour globally
        deny: scan(target) if rate_count("scan", "*", "1h") > 100
    }

    # ---------------------------------------------------------------------------
    # Agent behavior
    # ---------------------------------------------------------------------------

    with memory = "persistent", timeout = "10m" {

        # Phase 1: Plan the scan
        # The LLM analyzes the request and proposes an nmap command.
        # It has access to scan history via the vector store for context.

        let scan_history = recall("scans", input.target_description, limit: 5)

        let scan_plan = reason("""
            You are a network security analyst. Given the following request,
            determine the appropriate nmap scan to execute.

            Request: {input.prompt}
            Allowed CIDRs: {context.allowed_cidrs}
            Previous scans on similar targets: {scan_history}

            Determine:
            1. Target IP/CIDR (must be within allowed ranges)
            2. Scan type (ping, service, version, syn, os_detect, aggressive)
            3. Specific nmap flags
            4. Risk assessment (low, medium, high)
            5. Justification for the chosen scan type

            If the request asks to scan targets outside allowed ranges, say so
            explicitly -- do not attempt to scan them.

            Respond with a structured scan plan.
        """)

        # Phase 2: Execute the scan
        # The plan goes through the ORGA Gate. Cedar policies evaluate:
        #   - Is the target CIDR in allowed_cidrs?
        #   - Is the scan type permitted for this environment?
        #   - Are we within rate limits?
        #   - Does this scan type require human approval?
        #
        # If the Gate denies, the action is blocked and logged.
        # The LLM never sees the denial reason in a way that lets it
        # craft a bypass -- the Gate operates outside LLM influence.

        let scan_result = nmap_scan(
            target: scan_plan.target,
            scan_type: scan_plan.scan_type,
            flags: scan_plan.flags,
            output_format: "xml"
        )

        # Phase 3: Parse and interpret results
        let parsed = parse_nmap_xml(scan_result.output_file)

        # Phase 4: AI-powered analysis
        # Second ORGA pass: the LLM interprets results and generates
        # a prioritized report with remediation recommendations.

        let analysis = reason("""
            You are a network security analyst. Analyze these nmap scan results
            and produce a security assessment.

            Scan results: {parsed}
            Target: {scan_plan.target}
            Scan type: {scan_plan.scan_type}

            For each finding:
            1. Severity (critical, high, medium, low, informational)
            2. Service and version identified
            3. Known CVEs (cross-reference with lookup_cve)
            4. Remediation recommendation
            5. Priority (immediate, soon, planned, monitor)

            Produce a structured report sorted by severity.
        """)

        # Store results for future context
        store("scans", {
            target: scan_plan.target,
            scan_type: scan_plan.scan_type,
            timestamp: now(),
            findings_count: parsed.hosts_count,
            severity_summary: analysis.severity_summary
        })

        # Return the structured report
        return ScanReport {
            target: scan_plan.target,
            scan_type: scan_plan.scan_type,
            raw_results: parsed,
            analysis: analysis,
            audit_id: context.audit_entry_id
        }
    }
}

# ---------------------------------------------------------------------------
# Type definitions
# ---------------------------------------------------------------------------

type ScanRequest {
    prompt: string                  # Natural language scan request
    target_description: string      # For vector similarity search
    requester: string               # Identity of the person requesting
    priority: string                # "routine" | "urgent" | "incident_response"
}

type ScanReport {
    target: string
    scan_type: string
    raw_results: NmapResults
    analysis: SecurityAnalysis
    audit_id: string                # Links to the cryptographic audit entry
}

type NmapResults {
    hosts_count: number
    hosts: list<HostResult>
    scan_duration_seconds: number
}

type HostResult {
    ip: string
    hostname: string
    state: string                   # "up" | "down" | "filtered"
    ports: list<PortResult>
    os_guess: string
}

type PortResult {
    port: number
    protocol: string                # "tcp" | "udp"
    state: string                   # "open" | "closed" | "filtered"
    service: string
    version: string
    cves: list<string>
}

type SecurityAnalysis {
    severity_summary: SeveritySummary
    findings: list<Finding>
    recommendations: list<Recommendation>
}

type SeveritySummary {
    critical: number
    high: number
    medium: number
    low: number
    informational: number
}

type Finding {
    severity: string
    title: string
    description: string
    affected_host: string
    affected_port: number
    cve_ids: list<string>
}

type Recommendation {
    priority: string
    action: string
    affected_findings: list<string>
    estimated_effort: string
}

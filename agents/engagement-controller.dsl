// Top-level penetration test orchestrator -- PTES methodology
//
// This agent orchestrates a full penetration test by delegating to
// specialist phase agents. It maintains engagement state, enforces
// phase ordering, and decides transitions based on cumulative findings.
//
// Phase flow:
//   1. recon       -- Network discovery, fingerprinting, CVE lookup
//   2. enum        -- Service enumeration (web, SMB, SNMP)
//   3. vuln-assess -- Vulnerability scanning (nuclei, sqlmap detect, NSE)
//   4. exploit     -- Exploitation (HUMAN APPROVAL REQUIRED)
//   5. post-exploit-- Lateral movement (HUMAN APPROVAL + SCOPE REVALIDATION)
//   6. reporter    -- Report generation (executive, technical, remediation)
//
// After each phase completes the controller invokes the reflector agent
// (policies/reflector.cedar), which reads the phase's findings and writes
// subject-predicate-object lessons into the knowledge store. The next
// phase's agent pulls those lessons via recall_knowledge before planning,
// so learning flows forward across the engagement without any agent
// mutating another agent's tools or policy.
//
// Phase transition rules:
//   - recon -> enum: requires at least 1 recon finding
//   - enum -> vuln: requires at least 1 enumeration finding
//   - vuln -> exploit: requires at least 1 exploitable vulnerability
//   - exploit -> post-exploit: requires at least 1 successful exploit
//   - post-exploit -> reporter: always allowed
//
// ORGA flow per phase:
//   OBSERVE: Check engagement state and phase completion status
//   REASON:  Decide next phase based on findings and methodology
//   GATE:    Cedar evaluates phase transition policies
//   ACT:     Delegate to phase agent, collect results, update state

metadata {
    version: "1.0.0",
    author: "thirdkey-ai",
    description: "Multi-phase penetration test engagement orchestrator"
}

agent engagement_controller {
    capabilities: [create_engagement, manage_engagement, query_findings, generate_report, compare_engagements]

    policy phase_gate {
        allow: transition(next_phase)
        require: current_phase_complete
        deny: skip_phase
        audit: all_operations
    }

    function orchestrate(input: String) -> Result<String> {
        let request = parse_json(input);
        let engagement_id = request.engagement_id;
        let target = request.target;

        // Initialize engagement
        let engagement = create_engagement(client, scope, start_date, end_date);

        // Phase 1: Reconnaissance
        // Delegate to recon agent with target list
        // Recon discovers hosts, services, and initial CVEs
        let recon_result = invoke_agent("recon", engagement_id, targets);
        invoke_agent("reflector", engagement_id, phase: "recon");

        // Phase 2: Enumeration (requires recon findings)
        // Delegate to enum agent with discovered services
        let enum_result = invoke_agent("enum", engagement_id, recon_result.services);
        invoke_agent("reflector", engagement_id, phase: "enum");

        // Phase 3: Vulnerability Assessment (requires enum findings)
        // Delegate to vuln-assess agent with enumerated targets
        let vuln_result = invoke_agent("vuln-assess", engagement_id, enum_result.targets);
        invoke_agent("reflector", engagement_id, phase: "vuln");

        // Phase 4: Exploitation (requires exploitable vulns + HUMAN APPROVAL)
        // Delegate to exploit agent -- operator must approve each exploit
        let exploit_result = invoke_agent("exploit", engagement_id, vuln_result.vulnerabilities);
        invoke_agent("reflector", engagement_id, phase: "exploit");

        // Phase 5: Post-Exploitation (requires successful exploit + HUMAN APPROVAL)
        // Delegate to post-exploit agent -- operator approves + scope revalidation
        let post_exploit_result = invoke_agent("post-exploit", engagement_id, exploit_result.sessions);
        invoke_agent("reflector", engagement_id, phase: "post_exploit");

        // Phase 6: Reporting (always allowed)
        // Generate executive, technical, and remediation reports; reporter
        // reads the accumulated reflector knowledge for the narrative sections.
        let report_result = invoke_agent("reporter", engagement_id, report_types);

        // Finalize engagement
        let finalized = manage_engagement(engagement_id, status: "complete");
        return json_encode(engagement_report);
    }
}

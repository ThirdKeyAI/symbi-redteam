// =============================================================================
// engagement-controller.dsl -- Top-level penetration test orchestrator
//
// This agent orchestrates a full PTES-methodology pen test by delegating
// to specialist phase agents via Symbiont's inter-agent communication bus.
// It maintains engagement state, enforces phase ordering, and decides
// transitions based on cumulative findings.
//
// ORGA flow:
//   OBSERVE: Load engagement state, check phase completion status
//   REASON:  Decide next phase based on findings and methodology
//   GATE:    Cedar evaluates phase transition policies
//   ACT:     Delegate to phase agent via ask(), collect results
//   (loop for each phase: recon → enum → vuln → exploit → post-exploit → report)
// =============================================================================

metadata {
    version = "1.0.0"
    author = "thirdkey-ai"
    description = "Multi-phase penetration test engagement orchestrator"
    license = "Apache-2.0"
    tags = ["security", "pentest", "orchestration", "multi-agent", "PTES"]
}

agent engagement_controller(input: EngagementRequest) -> EngagementReport {

    capabilities = [
        "agent.ask",               // Synchronous inter-agent communication
        "agent.parallel",          // Concurrent agent calls
        "agent.spawn",             // Spawn phase agents
        "tool.create_engagement",  // Initialize engagement record
        "tool.manage_engagement",  // Update engagement status
        "tool.query_findings",     // Query evidence database
        "tool.generate_report",    // Generate final reports
        "tool.compare_engagements", // Retest comparison
        "memory.read",             // Read engagement state
        "memory.write",            // Persist engagement state
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
        capabilities = [Network.Raw, Network.Admin]
    }

    policy engagement_orchestration {
        allow: orchestrate(phase) if phase in ["recon", "enum", "vuln", "exploit", "post_exploit", "reporting"]
        deny: orchestrate(phase) if engagement.status != "active"
        audit: all_operations
    }

    memory engagement_state {
        store     markdown
        path      "data/engagement"
        retention 365d
        search {
            vector_weight  0.5
            keyword_weight 0.5
        }
    }

    with memory = "persistent", timeout = 0 {

        // Phase 1: Initialize engagement
        let engagement = create_engagement(
            client: input.client,
            start_date: input.start_date,
            end_date: input.end_date
        )

        store("engagement", {
            engagement_id: engagement.engagement_id,
            client: input.client,
            status: "active",
            current_phase: "initialized",
            phases_completed: [],
            total_findings: 0
        })

        log("INFO", "Engagement initialized: " + engagement.engagement_id)

        // Phase 2: Reconnaissance
        log("INFO", "Starting reconnaissance phase")
        store("engagement", { current_phase: "recon" })

        let recon_message = json_encode({
            engagement_id: engagement.engagement_id,
            targets: input.targets,
            scope: input.scope_description
        })

        let recon_result = ask("recon", recon_message)
        let recon_data = parse_json(recon_result)

        store("engagement", {
            current_phase: "recon_complete",
            phases_completed: ["recon"],
            recon_findings: recon_data.findings_count,
            total_findings: recon_data.findings_count
        })

        log("INFO", "Recon complete: " + recon_data.findings_count + " findings")

        // Phase 3: Enumeration
        // Gate: requires at least 1 recon finding (enforced by phase-gates.cedar)
        if recon_data.findings_count > 0 {
            log("INFO", "Starting enumeration phase")
            store("engagement", { current_phase: "enum" })

            let enum_message = json_encode({
                engagement_id: engagement.engagement_id,
                targets: recon_data.discovered_hosts,
                services: recon_data.discovered_services,
                scope: input.scope_description
            })

            let enum_result = ask("enum", enum_message)
            let enum_data = parse_json(enum_result)

            let running_total = recon_data.findings_count + enum_data.findings_count

            store("engagement", {
                current_phase: "enum_complete",
                phases_completed: ["recon", "enum"],
                enum_findings: enum_data.findings_count,
                total_findings: running_total
            })

            log("INFO", "Enumeration complete: " + enum_data.findings_count + " findings")

            // Phase 4: Vulnerability Assessment
            log("INFO", "Starting vulnerability assessment phase")
            store("engagement", { current_phase: "vuln" })

            let vuln_message = json_encode({
                engagement_id: engagement.engagement_id,
                targets: enum_data.enumerated_targets,
                services: enum_data.discovered_services,
                web_apps: enum_data.web_applications,
                scope: input.scope_description
            })

            let vuln_result = ask("vuln-assess", vuln_message)
            let vuln_data = parse_json(vuln_result)

            running_total = running_total + vuln_data.findings_count

            store("engagement", {
                current_phase: "vuln_complete",
                phases_completed: ["recon", "enum", "vuln"],
                vuln_findings: vuln_data.findings_count,
                total_findings: running_total
            })

            log("INFO", "Vuln assessment complete: " + vuln_data.findings_count + " findings")

            // Phase 5: Exploitation (human-gated)
            // Gate: requires vuln findings reviewed by human (escalation.cedar)
            if vuln_data.exploitable_count > 0 {
                log("INFO", "Starting exploitation phase (requires human approval per target)")
                store("engagement", { current_phase: "exploit" })

                let exploit_message = json_encode({
                    engagement_id: engagement.engagement_id,
                    vulnerabilities: vuln_data.exploitable_findings,
                    targets: vuln_data.vulnerable_targets,
                    credentials: enum_data.discovered_credentials,
                    scope: input.scope_description
                })

                let exploit_result = ask("exploit", exploit_message)
                let exploit_data = parse_json(exploit_result)

                running_total = running_total + exploit_data.findings_count

                store("engagement", {
                    current_phase: "exploit_complete",
                    phases_completed: ["recon", "enum", "vuln", "exploit"],
                    exploit_findings: exploit_data.findings_count,
                    exploit_successes: exploit_data.success_count,
                    total_findings: running_total
                })

                log("INFO", "Exploitation complete: " + exploit_data.success_count + " successful exploits")

                // Phase 6: Post-Exploitation (human-gated + scope revalidation)
                if exploit_data.success_count > 0 {
                    log("INFO", "Starting post-exploitation phase (requires human approval + scope revalidation)")
                    store("engagement", { current_phase: "post_exploit" })

                    let postexploit_message = json_encode({
                        engagement_id: engagement.engagement_id,
                        sessions: exploit_data.active_sessions,
                        compromised_hosts: exploit_data.compromised_hosts,
                        credentials: exploit_data.discovered_credentials,
                        scope: input.scope_description
                    })

                    let postexploit_result = ask("post-exploit", postexploit_message)
                    let postexploit_data = parse_json(postexploit_result)

                    running_total = running_total + postexploit_data.findings_count

                    store("engagement", {
                        current_phase: "post_exploit_complete",
                        phases_completed: ["recon", "enum", "vuln", "exploit", "post_exploit"],
                        postexploit_findings: postexploit_data.findings_count,
                        total_findings: running_total
                    })

                    log("INFO", "Post-exploitation complete: " + postexploit_data.findings_count + " findings")
                }
            }
        }

        // Phase 7: Report Generation
        log("INFO", "Starting report generation phase")
        store("engagement", { current_phase: "reporting" })

        let report_message = json_encode({
            engagement_id: engagement.engagement_id,
            report_types: ["executive", "technical", "remediation"],
            output_formats: ["markdown", "html", "pdf"],
            baseline_engagement_id: input.baseline_engagement_id
        })

        let report_result = ask("reporter", report_message)
        let report_data = parse_json(report_result)

        // Finalize engagement
        manage_engagement(
            engagement_id: engagement.engagement_id,
            status: "complete"
        )

        store("engagement", {
            current_phase: "complete",
            phases_completed: recall("engagement", "phases_completed"),
            total_findings: running_total,
            reports_generated: report_data.reports_count
        })

        log("INFO", "Engagement complete: " + engagement.engagement_id)

        return EngagementReport {
            engagement_id: engagement.engagement_id,
            client: input.client,
            total_findings: running_total,
            reports: report_data.report_paths,
            phases_completed: recall("engagement", "phases_completed"),
            audit_id: context.audit_entry_id
        }
    }
}

// ---------------------------------------------------------------------------
// Type definitions
// ---------------------------------------------------------------------------

type EngagementRequest {
    client: string
    start_date: string
    end_date: string
    targets: list<string>
    scope_description: string
    baseline_engagement_id: string    // For retest comparison (empty if first engagement)
}

type EngagementReport {
    engagement_id: string
    client: string
    total_findings: number
    reports: list<string>
    phases_completed: list<string>
    audit_id: string
}

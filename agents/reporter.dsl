// =============================================================================
// reporter.dsl -- Report generation phase agent
//
// Generates executive, technical, and remediation reports from the evidence
// database. Can also produce retest comparison reports. Supports Markdown,
// HTML, and PDF output formats.
// =============================================================================

metadata {
    version = "1.0.0"
    author = "thirdkey-ai"
    description = "Automated penetration test report generator"
    license = "Apache-2.0"
    tags = ["security", "reporting", "compliance", "documentation"]
}

agent reporter(input: ReportRequest) -> ReportResult {

    capabilities = [
        "tool.generate_report",
        "tool.compare_engagements",
        "tool.query_findings",
        "tool.search_similar_findings",
        "tool.store_tool_run",
        "tool.capture_evidence",
        "memory.read",
        "memory.write",
    ]

    resources {
        memory = 256MB
        cpu = 1000ms
        network = deny
        storage = 200MB
    }

    security {
        tier = Tier1
        sandbox = strict
        capabilities = []
    }

    policy report_authorization {
        allow: report(engagement) if engagement.status in ["active", "complete"]
        audit: all_operations
    }

    with memory = "persistent", timeout = 600000 {

        let request = parse_json(input.message)
        let engagement_id = request.engagement_id
        let report_types = request.report_types
        let output_formats = request.output_formats
        let baseline_id = request.baseline_engagement_id
        let report_paths = []
        let reports_count = 0

        // Review findings before generating reports
        let all_findings = query_findings(engagement_id: engagement_id)

        let report_plan = reason("""
            You are a penetration test report writer. Review the findings
            and prepare to generate reports.

            Total findings: {all_findings.findings_count}
            Findings: {all_findings.findings}

            For the executive report:
            - Highlight the most critical findings
            - Provide a clear risk summary
            - Use non-technical language

            For the technical report:
            - Include all findings with full detail
            - Provide reproduction steps where available
            - Include evidence references

            For the remediation report:
            - Prioritize by severity
            - Group related findings
            - Provide specific, actionable guidance
        """)

        // Generate each report type in each format
        for report_type in report_types {
            for format in output_formats {
                let report = generate_report(
                    engagement_id: engagement_id,
                    report_type: report_type,
                    output_format: format
                )

                store_tool_run(
                    engagement_id: engagement_id,
                    tool: "generate_report",
                    command: "generate_report " + report_type + " " + format,
                    arguments: json_encode({report_type: report_type, output_format: format}),
                    exit_code: 0,
                    duration_ms: 0,
                    output_file: report.report_path,
                    cedar_decision: "allow"
                )

                capture_evidence(
                    engagement_id: engagement_id,
                    source_path: report.report_path,
                    description: report_type + " report in " + format + " format"
                )

                report_paths = report_paths + [report.report_path]
                reports_count = reports_count + 1

                log("INFO", "Generated " + report_type + " report (" + format + "): " + report.report_path)
            }
        }

        // Generate retest comparison if baseline provided
        if baseline_id != "" {
            for format in output_formats {
                let comparison = compare_engagements(
                    engagement_id: engagement_id,
                    baseline_engagement_id: baseline_id,
                    output_format: format
                )

                store_tool_run(
                    engagement_id: engagement_id,
                    tool: "compare_engagements",
                    command: "compare_engagements " + engagement_id + " vs " + baseline_id,
                    arguments: json_encode({baseline: baseline_id, format: format}),
                    exit_code: 0,
                    duration_ms: 0,
                    output_file: comparison.report_path,
                    cedar_decision: "allow"
                )

                report_paths = report_paths + [comparison.report_path]
                reports_count = reports_count + 1

                log("INFO", "Retest comparison (" + format + "): " +
                    comparison.remediated + " remediated, " +
                    comparison.persistent + " persistent, " +
                    comparison.regressed + " regressed, " +
                    comparison.new_findings + " new")
            }
        }

        store("reports", {
            engagement_id: engagement_id,
            timestamp: now(),
            reports_count: reports_count,
            report_paths: report_paths
        })

        return json_encode(ReportResult {
            engagement_id: engagement_id,
            reports_count: reports_count,
            report_paths: report_paths,
            phase: "reporting",
            status: "complete"
        })
    }
}

type ReportRequest {
    message: string
}

type ReportResult {
    engagement_id: string
    reports_count: number
    report_paths: list<string>
    phase: string
    status: string
}

// Report generation phase agent -- produce engagement deliverables
//
// ORGA flow:
//   OBSERVE: Load all findings from evidence database
//   REASON:  Organize findings by severity, phase, and target
//   GATE:    Cedar evaluates (reporting always allowed during engagement)
//   ACT:     Generate reports in requested formats
//
// Workflow:
//   1. Query all findings for the engagement
//   2. Generate executive summary report (high-level, business audience)
//   3. Generate technical report (detailed findings, remediation steps)
//   4. Generate remediation report (prioritized fix list)
//   5. Optionally compare with baseline engagement for retest delta
//   6. Output in markdown, HTML, or PDF format

metadata {
    version: "1.0.0",
    author: "thirdkey-ai",
    description: "Automated penetration test report generator"
}

agent reporter {
    capabilities: [generate_report, compare_engagements, query_findings, search_similar_findings, store_tool_run, capture_evidence]

    policy report_authorization {
        allow: report(engagement)
        audit: all_operations
    }

    function execute_report(input: String) -> Result<String> {
        let request = parse_json(input);
        let engagement_id = request.engagement_id;
        let report_types = request.report_types;
        let output_formats = request.output_formats;

        // Query all findings
        let findings = query_findings(engagement_id);

        // Generate requested report types
        let executive_report = generate_report(engagement_id, report_type: "executive", output_format: "markdown");
        let technical_report = generate_report(engagement_id, report_type: "technical", output_format: "markdown");
        let remediation_report = generate_report(engagement_id, report_type: "remediation", output_format: "markdown");

        // Optional: retest comparison
        let baseline_id = request.baseline_engagement_id;
        if baseline_id {
            let delta = compare_engagements(engagement_id, baseline_id);
        }

        return json_encode(report_result);
    }
}

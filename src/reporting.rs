// =============================================================================
// reporting.rs -- MCP tool definitions for report generation
//
// Generates executive, technical, and remediation reports from the evidence
// database. Supports Markdown, HTML, and PDF output formats. Also handles
// engagement lifecycle and retest comparison.
// =============================================================================

use serde::{Deserialize, Serialize};
use crate::types::{ToolDefinition, ToolError, validate_engagement_id, validate_allowlist};
use std::fs;
use std::process::Command;

// ---------------------------------------------------------------------------
// generate_report -- Produce engagement reports in multiple formats
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GenerateReportInput {
    /// Engagement ID to generate report for
    pub engagement_id: String,
    /// Report type: executive, technical, remediation
    pub report_type: String,
    /// Output format: markdown, html, pdf
    #[serde(default = "default_format")]
    pub output_format: String,
}

fn default_format() -> String {
    "markdown".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateReportOutput {
    pub report_path: String,
    pub report_type: String,
    pub output_format: String,
    pub pages: usize,
    pub status: String,
}

pub fn generate_report(input: GenerateReportInput) -> Result<GenerateReportOutput, ToolError> {
    // Validate engagement_id to prevent directory traversal in report paths
    validate_engagement_id(&input.engagement_id)?;

    validate_allowlist(&input.report_type, "report_type", &["executive", "technical", "remediation"])?;

    let valid_formats = ["markdown", "html", "pdf"];
    if !valid_formats.contains(&input.output_format.as_str()) {
        return Err(ToolError::InvalidInput(format!(
            "Invalid format '{}'. Must be one of: {}",
            input.output_format,
            valid_formats.join(", ")
        )));
    }

    let db_path = std::env::var("SYMBI_DB_PATH")
        .unwrap_or_else(|_| "/app/.symbiont/data/redteam.db".to_string());

    let conn = crate::db::init_db(&db_path)
        .map_err(|e| ToolError::ExecutionFailed(format!("Database error: {e}")))?;

    // Load engagement data
    let engagement = crate::db::get_engagement(&conn, &input.engagement_id)
        .map_err(|e| ToolError::ExecutionFailed(format!("Query error: {e}")))?
        .ok_or_else(|| ToolError::ExecutionFailed(format!(
            "Engagement not found: {}", input.engagement_id
        )))?;

    // Load summary statistics
    let summary = crate::db::get_engagement_summary(&conn, &input.engagement_id)
        .map_err(|e| ToolError::ExecutionFailed(format!("Summary error: {e}")))?;

    // Load all findings for this engagement
    let findings = crate::db::query_findings(&conn, &input.engagement_id, None, None, None)
        .map_err(|e| ToolError::ExecutionFailed(format!("Findings query error: {e}")))?;

    // Load tool runs
    let tool_runs = crate::db::get_tool_runs(&conn, &input.engagement_id, None)
        .map_err(|e| ToolError::ExecutionFailed(format!("Tool runs query error: {e}")))?;

    // Read the template (report_type is already validated via allowlist)
    let template_name = format!("report-{}.md", input.report_type);
    let template_path = format!("/app/templates/{}", template_name);
    assert!(template_path.starts_with("/app/templates/"), "template path escaped prefix");
    let template = fs::read_to_string(&template_path)
        .map_err(|e| ToolError::ExecutionFailed(format!("Template read error: {e}")))?;

    // Generate markdown content by populating the template
    let markdown = populate_report_template(
        &template,
        &engagement,
        &summary,
        &findings,
        &tool_runs,
        &input.report_type,
    );

    // Determine output paths
    let reports_dir = format!("/app/.symbiont/reports/{}", input.engagement_id);
    fs::create_dir_all(&reports_dir)
        .map_err(|e| ToolError::ExecutionFailed(format!("Failed to create reports dir: {e}")))?;

    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let base_name = format!("{}-{}-{}", input.engagement_id, input.report_type, timestamp);

    // Write markdown first (always needed as intermediate)
    let md_path = format!("{}/{}.md", reports_dir, base_name);
    fs::write(&md_path, &markdown)
        .map_err(|e| ToolError::ExecutionFailed(format!("Write error: {e}")))?;

    let final_path = match input.output_format.as_str() {
        "markdown" => md_path.clone(),
        "html" => {
            let html_path = format!("{}/{}.html", reports_dir, base_name);
            let output = Command::new("pandoc")
                .args([
                    &md_path,
                    "-f", "markdown",
                    "-t", "html5",
                    "--standalone",
                    "--metadata", &format!("title=Penetration Test Report - {}", engagement.client),
                    "--css", "https://cdn.simplecss.org/simple.min.css",
                    "-o", &html_path,
                ])
                .output()
                .map_err(|e| ToolError::ExecutionFailed(format!("pandoc failed: {e}")))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(ToolError::ExecutionFailed(format!("pandoc error: {stderr}")));
            }
            html_path
        }
        "pdf" => {
            let pdf_path = format!("{}/{}.pdf", reports_dir, base_name);
            let output = Command::new("pandoc")
                .args([
                    &md_path,
                    "-f", "markdown",
                    "--pdf-engine=weasyprint",
                    "--metadata", &format!("title=Penetration Test Report - {}", engagement.client),
                    "-o", &pdf_path,
                ])
                .output()
                .map_err(|e| ToolError::ExecutionFailed(format!("pandoc failed: {e}")))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(ToolError::ExecutionFailed(format!("pandoc error: {stderr}")));
            }
            pdf_path
        }
        _ => unreachable!(),
    };

    // Estimate page count (rough: ~50 lines per page for technical, ~25 for executive)
    let line_count = markdown.lines().count();
    let pages = match input.report_type.as_str() {
        "executive" => (line_count / 25).max(1),
        _ => (line_count / 50).max(1),
    };

    Ok(GenerateReportOutput {
        report_path: final_path,
        report_type: input.report_type,
        output_format: input.output_format,
        pages,
        status: "generated".to_string(),
    })
}

/// Populate a report template with engagement data.
fn populate_report_template(
    template: &str,
    engagement: &crate::db::Engagement,
    summary: &crate::db::EngagementSummary,
    findings: &[crate::db::Finding],
    tool_runs: &[crate::db::ToolRun],
    report_type: &str,
) -> String {
    let mut content = template.to_string();

    // Replace template variables
    content = content.replace("{{engagement_id}}", &engagement.id);
    content = content.replace("{{client}}", &engagement.client);
    content = content.replace("{{start_date}}", &engagement.start_date);
    content = content.replace("{{end_date}}", &engagement.end_date);
    content = content.replace("{{status}}", &engagement.status);
    content = content.replace("{{total_findings}}", &summary.total_findings.to_string());
    content = content.replace("{{critical_count}}", &summary.critical_count.to_string());
    content = content.replace("{{high_count}}", &summary.high_count.to_string());
    content = content.replace("{{medium_count}}", &summary.medium_count.to_string());
    content = content.replace("{{low_count}}", &summary.low_count.to_string());
    content = content.replace("{{info_count}}", &summary.info_count.to_string());
    content = content.replace("{{total_tool_runs}}", &summary.total_tool_runs.to_string());
    content = content.replace(
        "{{phases_completed}}",
        &summary.phases_with_findings.join(", "),
    );
    content = content.replace("{{report_date}}", &chrono::Utc::now().format("%Y-%m-%d").to_string());

    // Generate findings section based on report type
    let findings_section = match report_type {
        "executive" => generate_executive_findings(findings),
        "technical" => generate_technical_findings(findings),
        "remediation" => generate_remediation_findings(findings),
        _ => String::new(),
    };
    content = content.replace("{{findings_section}}", &findings_section);

    // Generate tool runs summary
    let tools_section = generate_tools_summary(tool_runs);
    content = content.replace("{{tools_section}}", &tools_section);

    content
}

/// Generate executive-level findings summary (grouped by severity).
fn generate_executive_findings(findings: &[crate::db::Finding]) -> String {
    let mut output = String::new();

    for severity in &["critical", "high", "medium", "low", "info"] {
        let sev_findings: Vec<&crate::db::Finding> = findings
            .iter()
            .filter(|f| f.severity == *severity && !f.false_positive)
            .collect();

        if sev_findings.is_empty() {
            continue;
        }

        output.push_str(&format!(
            "\n### {} Severity ({} findings)\n\n",
            capitalize(severity),
            sev_findings.len()
        ));

        for f in &sev_findings {
            output.push_str(&format!("- **{}**", f.title));
            if let Some(ref ip) = f.target_ip {
                output.push_str(&format!(" ({})", ip));
            }
            output.push('\n');
        }
    }

    output
}

/// Generate technical findings with full details.
fn generate_technical_findings(findings: &[crate::db::Finding]) -> String {
    let mut output = String::new();

    for (idx, f) in findings.iter().filter(|f| !f.false_positive).enumerate() {
        output.push_str(&format!("\n### Finding {}: {}\n\n", idx + 1, f.title));
        output.push_str("| Field | Value |\n|-------|-------|\n");
        output.push_str(&format!("| Severity | {} |\n", f.severity.to_uppercase()));
        if let Some(ref ip) = f.target_ip {
            output.push_str(&format!("| Target | {} |\n", ip));
        }
        if let Some(port) = f.target_port {
            output.push_str(&format!("| Port | {} |\n", port));
        }
        if let Some(ref svc) = f.service {
            output.push_str(&format!("| Service | {} |\n", svc));
        }
        output.push_str(&format!("| Tool | {} |\n", f.tool));
        output.push_str(&format!("| Phase | {} |\n", f.phase));
        if let Some(score) = f.cvss_score {
            output.push_str(&format!("| CVSS Score | {:.1} |\n", score));
        }
        if let Some(ref cves) = f.cve_ids {
            output.push_str(&format!("| CVE IDs | {} |\n", cves));
        }
        output.push_str(&format!("| Verified | {} |\n", if f.verified { "Yes" } else { "No" }));
        output.push_str(&format!("| Date | {} |\n", f.created_at.as_deref().unwrap_or("N/A")));

        if let Some(ref desc) = f.description {
            output.push_str(&format!("\n**Description:**\n\n{}\n", desc));
        }
        if let Some(ref rem) = f.remediation {
            output.push_str(&format!("\n**Remediation:**\n\n{}\n", rem));
        }
        if let Some(ref ev) = f.evidence_path {
            output.push_str(&format!("\n**Evidence:** `{}`\n", ev));
        }
    }

    output
}

/// Generate remediation-focused findings grouped by priority and effort.
fn generate_remediation_findings(findings: &[crate::db::Finding]) -> String {
    let mut output = String::new();

    // Group by severity as priority proxy
    let priority_order = ["critical", "high", "medium", "low"];
    let effort_labels = ["Immediate", "Short-term", "Medium-term", "Long-term"];

    for (priority, effort) in priority_order.iter().zip(effort_labels.iter()) {
        let sev_findings: Vec<&crate::db::Finding> = findings
            .iter()
            .filter(|f| f.severity == *priority && !f.false_positive)
            .collect();

        if sev_findings.is_empty() {
            continue;
        }

        output.push_str(&format!(
            "\n### {} Priority — {} Action ({} items)\n\n",
            capitalize(priority),
            effort,
            sev_findings.len()
        ));

        output.push_str("| # | Finding | Target | Remediation |\n");
        output.push_str("|---|---------|--------|-------------|\n");

        for (idx, f) in sev_findings.iter().enumerate() {
            let target = f.target_ip.as_deref().unwrap_or("N/A");
            let remediation = f.remediation.as_deref().unwrap_or("See technical report");
            output.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                idx + 1,
                f.title,
                target,
                remediation
            ));
        }
    }

    output
}

/// Generate tool runs summary table.
fn generate_tools_summary(tool_runs: &[crate::db::ToolRun]) -> String {
    let mut output = String::new();
    output.push_str("| Tool | Runs | Avg Duration | Success Rate |\n");
    output.push_str("|------|------|-------------|-------------|\n");

    // Group by tool name
    let mut tool_groups: std::collections::HashMap<&str, Vec<&crate::db::ToolRun>> =
        std::collections::HashMap::new();
    for tr in tool_runs {
        tool_groups.entry(&tr.tool).or_default().push(tr);
    }

    let mut tools: Vec<&&str> = tool_groups.keys().collect();
    tools.sort();

    for tool in tools {
        let runs = &tool_groups[tool];
        let count = runs.len();
        let avg_duration: f64 = runs
            .iter()
            .filter_map(|r| r.duration_ms)
            .map(|d| d as f64)
            .sum::<f64>()
            / count.max(1) as f64;
        let success_count = runs.iter().filter(|r| r.exit_code == Some(0)).count();
        let success_rate = if count > 0 {
            (success_count as f64 / count as f64) * 100.0
        } else {
            0.0
        };

        output.push_str(&format!(
            "| {} | {} | {:.0}ms | {:.0}% |\n",
            tool, count, avg_duration, success_rate
        ));
    }

    output
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

// ---------------------------------------------------------------------------
// compare_engagements -- Retest delta report
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CompareEngagementsInput {
    /// Current (retest) engagement ID
    pub engagement_id: String,
    /// Baseline engagement ID to compare against
    pub baseline_engagement_id: String,
    /// Output format: markdown, html, pdf
    #[serde(default = "default_format")]
    pub output_format: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompareEngagementsOutput {
    pub report_path: String,
    pub remediated: usize,
    pub persistent: usize,
    pub regressed: usize,
    pub new_findings: usize,
    pub status: String,
}

pub fn compare_engagements(input: CompareEngagementsInput) -> Result<CompareEngagementsOutput, ToolError> {
    validate_engagement_id(&input.engagement_id)?;
    validate_engagement_id(&input.baseline_engagement_id)?;

    let db_path = std::env::var("SYMBI_DB_PATH")
        .unwrap_or_else(|_| "/app/.symbiont/data/redteam.db".to_string());

    let conn = crate::db::init_db(&db_path)
        .map_err(|e| ToolError::ExecutionFailed(format!("Database error: {e}")))?;

    // Load both engagements' findings
    let current = crate::db::query_findings(&conn, &input.engagement_id, None, None, None)
        .map_err(|e| ToolError::ExecutionFailed(format!("Current findings error: {e}")))?;

    let baseline = crate::db::query_findings(&conn, &input.baseline_engagement_id, None, None, None)
        .map_err(|e| ToolError::ExecutionFailed(format!("Baseline findings error: {e}")))?;

    // Match findings by target_ip + target_port + title similarity
    let mut remediated = Vec::new();
    let mut persistent = Vec::new();
    let mut regressed = Vec::new();
    let mut new_findings = Vec::new();

    let mut matched_baseline_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    for current_finding in &current {
        let mut best_match: Option<&crate::db::Finding> = None;

        for baseline_finding in &baseline {
            if matched_baseline_ids.contains(&baseline_finding.id) {
                continue;
            }
            // Match on target + title
            if current_finding.target_ip == baseline_finding.target_ip
                && current_finding.target_port == baseline_finding.target_port
                && current_finding.title == baseline_finding.title
            {
                best_match = Some(baseline_finding);
                break;
            }
        }

        match best_match {
            Some(bl) => {
                matched_baseline_ids.insert(bl.id.clone());

                // Determine if regressed (severity increased) or persistent
                let sev_order = |s: &str| -> u8 {
                    match s {
                        "critical" => 5,
                        "high" => 4,
                        "medium" => 3,
                        "low" => 2,
                        "info" => 1,
                        _ => 0,
                    }
                };

                if sev_order(&current_finding.severity) > sev_order(&bl.severity) {
                    regressed.push((current_finding, bl));
                } else {
                    persistent.push((current_finding, bl));
                }

                // Record retest entry
                let _ = crate::db::insert_retest(
                    &conn,
                    &input.engagement_id,
                    &input.baseline_engagement_id,
                    &current_finding.id,
                    &bl.id,
                    if sev_order(&current_finding.severity) > sev_order(&bl.severity) {
                        "regressed"
                    } else {
                        "persistent"
                    },
                    None,
                );
            }
            None => {
                new_findings.push(current_finding);

                let _ = crate::db::insert_retest(
                    &conn,
                    &input.engagement_id,
                    &input.baseline_engagement_id,
                    &current_finding.id,
                    &current_finding.id, // self-reference for new findings
                    "new",
                    None,
                );
            }
        }
    }

    // Baseline findings not matched = remediated
    for bl in &baseline {
        if !matched_baseline_ids.contains(&bl.id) && !bl.false_positive {
            remediated.push(bl);

            let _ = crate::db::insert_retest(
                &conn,
                &input.engagement_id,
                &input.baseline_engagement_id,
                &bl.id, // reference baseline finding
                &bl.id,
                "remediated",
                None,
            );
        }
    }

    // Generate comparison report
    let mut markdown = String::from("# Retest Comparison Report\n\n");
    markdown.push_str(&format!("**Current Engagement:** {}\n\n", input.engagement_id));
    markdown.push_str(&format!("**Baseline Engagement:** {}\n\n", input.baseline_engagement_id));
    markdown.push_str(&format!("**Report Date:** {}\n\n", chrono::Utc::now().format("%Y-%m-%d")));

    markdown.push_str("## Summary\n\n");
    markdown.push_str("| Status | Count |\n|--------|-------|\n");
    markdown.push_str(&format!("| Remediated | {} |\n", remediated.len()));
    markdown.push_str(&format!("| Persistent | {} |\n", persistent.len()));
    markdown.push_str(&format!("| Regressed | {} |\n", regressed.len()));
    markdown.push_str(&format!("| New | {} |\n", new_findings.len()));

    if !remediated.is_empty() {
        markdown.push_str("\n## Remediated Findings\n\n");
        for f in &remediated {
            markdown.push_str(&format!("- ~~{}~~ ({})\n", f.title, f.severity));
        }
    }

    if !persistent.is_empty() {
        markdown.push_str("\n## Persistent Findings\n\n");
        for (curr, _bl) in &persistent {
            markdown.push_str(&format!("- **{}** — {} severity\n", curr.title, curr.severity));
        }
    }

    if !regressed.is_empty() {
        markdown.push_str("\n## Regressed Findings\n\n");
        for (curr, bl) in &regressed {
            markdown.push_str(&format!(
                "- **{}** — severity increased from {} to {}\n",
                curr.title, bl.severity, curr.severity
            ));
        }
    }

    if !new_findings.is_empty() {
        markdown.push_str("\n## New Findings\n\n");
        for f in &new_findings {
            markdown.push_str(&format!("- **{}** — {} severity\n", f.title, f.severity));
        }
    }

    // Write report
    let reports_dir = format!("/app/.symbiont/reports/{}", input.engagement_id);
    fs::create_dir_all(&reports_dir)
        .map_err(|e| ToolError::ExecutionFailed(format!("Failed to create reports dir: {e}")))?;

    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let base_name = format!("{}-comparison-{}", input.engagement_id, timestamp);
    let md_path = format!("{}/{}.md", reports_dir, base_name);
    fs::write(&md_path, &markdown)
        .map_err(|e| ToolError::ExecutionFailed(format!("Write error: {e}")))?;

    let final_path = match input.output_format.as_str() {
        "html" => {
            let html_path = format!("{}/{}.html", reports_dir, base_name);
            let _ = Command::new("pandoc")
                .args([&md_path, "-f", "markdown", "-t", "html5", "--standalone", "-o", &html_path])
                .output();
            html_path
        }
        "pdf" => {
            let pdf_path = format!("{}/{}.pdf", reports_dir, base_name);
            let _ = Command::new("pandoc")
                .args([&md_path, "-f", "markdown", "--pdf-engine=weasyprint", "-o", &pdf_path])
                .output();
            pdf_path
        }
        _ => md_path,
    };

    Ok(CompareEngagementsOutput {
        report_path: final_path,
        remediated: remediated.len(),
        persistent: persistent.len(),
        regressed: regressed.len(),
        new_findings: new_findings.len(),
        status: "generated".to_string(),
    })
}

// ---------------------------------------------------------------------------
// create_engagement -- Initialize a new engagement record
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CreateEngagementInput {
    /// Client name
    pub client: String,
    /// Engagement start date (ISO 8601)
    pub start_date: String,
    /// Engagement end date (ISO 8601)
    pub end_date: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateEngagementOutput {
    pub engagement_id: String,
    pub scope_hash: String,
    pub status: String,
}

pub fn create_engagement(input: CreateEngagementInput) -> Result<CreateEngagementOutput, ToolError> {
    let db_path = std::env::var("SYMBI_DB_PATH")
        .unwrap_or_else(|_| "/app/.symbiont/data/redteam.db".to_string());

    let conn = crate::db::init_db(&db_path)
        .map_err(|e| ToolError::ExecutionFailed(format!("Database error: {e}")))?;

    // Read scope.toml for hashing
    let scope_toml = fs::read_to_string("/app/scope/scope.toml")
        .unwrap_or_else(|_| "no-scope-loaded".to_string());

    let engagement_id = crate::db::create_engagement(
        &conn,
        &input.client,
        &scope_toml,
        &input.start_date,
        &input.end_date,
    )
    .map_err(|e| ToolError::ExecutionFailed(format!("Create failed: {e}")))?;

    let scope_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(scope_toml.as_bytes());
        format!("{:x}", hasher.finalize())
    };

    Ok(CreateEngagementOutput {
        engagement_id,
        scope_hash,
        status: "active".to_string(),
    })
}

// ---------------------------------------------------------------------------
// manage_engagement -- Update engagement status
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ManageEngagementInput {
    /// Engagement ID
    pub engagement_id: String,
    /// New status: planning, active, paused, complete
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManageEngagementOutput {
    pub engagement_id: String,
    pub status: String,
    pub updated: bool,
}

pub fn manage_engagement(input: ManageEngagementInput) -> Result<ManageEngagementOutput, ToolError> {
    validate_engagement_id(&input.engagement_id)?;
    let valid_statuses = ["planning", "active", "paused", "complete"];
    if !valid_statuses.contains(&input.status.as_str()) {
        return Err(ToolError::InvalidInput(format!(
            "Invalid status '{}'. Must be one of: {}",
            input.status,
            valid_statuses.join(", ")
        )));
    }

    let db_path = std::env::var("SYMBI_DB_PATH")
        .unwrap_or_else(|_| "/app/.symbiont/data/redteam.db".to_string());

    let conn = crate::db::init_db(&db_path)
        .map_err(|e| ToolError::ExecutionFailed(format!("Database error: {e}")))?;

    let rows = crate::db::update_engagement_status(&conn, &input.engagement_id, &input.status)
        .map_err(|e| ToolError::ExecutionFailed(format!("Update failed: {e}")))?;

    Ok(ManageEngagementOutput {
        engagement_id: input.engagement_id,
        status: input.status,
        updated: rows > 0,
    })
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

pub fn register_tools() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition::new("generate_report")
            .description("Generate a penetration test report (executive, technical, or \
                          remediation) from the evidence database. Supports markdown, HTML, \
                          and PDF output formats via pandoc.")
            .input_schema::<GenerateReportInput>()
            .cedar_resource("PenTest::ReportGenerator")
            .cedar_actions(&["PenTest::Action::execute_tool"]),
        ToolDefinition::new("compare_engagements")
            .description("Generate a retest comparison report between a current engagement and \
                          a baseline. Identifies remediated, persistent, regressed, and new \
                          findings by matching on target, port, and title.")
            .input_schema::<CompareEngagementsInput>()
            .cedar_resource("PenTest::ReportGenerator")
            .cedar_actions(&["PenTest::Action::execute_tool"]),
        ToolDefinition::new("create_engagement")
            .description("Initialize a new penetration test engagement in the evidence database. \
                          Records client, date range, and scope hash for integrity tracking.")
            .input_schema::<CreateEngagementInput>()
            .cedar_resource("PenTest::EvidenceStore")
            .cedar_actions(&["PenTest::Action::store_evidence"]),
        ToolDefinition::new("manage_engagement")
            .description("Update an engagement's status (planning, active, paused, complete).")
            .input_schema::<ManageEngagementInput>()
            .cedar_resource("PenTest::EvidenceStore")
            .cedar_actions(&["PenTest::Action::store_evidence"]),
    ]
}

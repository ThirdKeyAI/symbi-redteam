// =============================================================================
// tools.rs -- MCP tool definitions for the nmap reconnaissance agent
//
// These tools are what the agent's REASON phase can propose calling.
// Each proposed tool call goes through the ORGA GATE before execution.
// The LLM sees the tool schemas; Cedar policies govern whether any
// specific invocation is permitted.
//
// Tool call flow:
//   1. LLM proposes: nmap_scan(target="10.0.1.0/24", scan_type="service")
//   2. Runtime extracts the action and builds a Cedar request
//   3. Cedar evaluates against policies/*.cedar
//   4. If ALLOW: runtime executes the tool
//   5. If DENY: runtime returns a policy denial to the LLM (no execution)
//   6. Result (or denial) feeds back into the next OBSERVE phase
// =============================================================================

use serde::{Deserialize, Serialize};
use symbi_mcp::{Tool, ToolInput, ToolOutput, ToolError};
use std::process::Command;

/// Execute an nmap scan against a target.
///
/// This tool is gated by Cedar policies:
///   - scan-authorization.cedar: target CIDR and scan type validation
///   - rate-limits.cedar: scan frequency enforcement
///   - escalation.cedar: human approval for high-risk scan types
///
/// The agent CANNOT execute this tool without passing all three policy files.
#[derive(Debug, Serialize, Deserialize)]
pub struct NmapScanInput {
    /// Target IP address or CIDR range (must be in allowed_cidrs)
    pub target: String,

    /// Scan type: ping, service, version, syn, os_detect, aggressive, vuln_script
    pub scan_type: String,

    /// Additional nmap flags (optional, validated by wrapper script)
    #[serde(default)]
    pub flags: String,

    /// Output format: "xml" (default) or "json"
    #[serde(default = "default_output_format")]
    pub output_format: String,
}

fn default_output_format() -> String {
    "xml".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NmapScanOutput {
    pub status: String,
    pub output_file: String,
    pub scan_id: String,
    pub duration_ms: u64,
}

/// MCP tool: nmap_scan
///
/// Cedar resource attributes populated by the runtime before Gate evaluation:
///   - resource.cidr = input.target
///   - resource.scan_type = input.scan_type
///   - resource.environment = looked up from target registry
///   - resource.is_external = true if target is outside RFC 1918
///   - resource.is_first_scan = true if no scan history for this CIDR
pub fn nmap_scan(input: NmapScanInput) -> Result<NmapScanOutput, ToolError> {
    let scan_id = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        std::process::id()
    );

    let output = Command::new("/app/scripts/nmap-wrapper.sh")
        .arg(&input.target)
        .arg(&input.scan_type)
        .arg(&input.flags)
        .arg(&scan_id)
        .output()
        .map_err(|e| ToolError::ExecutionFailed(format!("nmap wrapper failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::ExecutionFailed(
            format!("nmap exited with {}: {stderr}", output.status)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: NmapScanOutput = serde_json::from_str(&stdout)
        .map_err(|e| ToolError::ParseError(format!("Failed to parse wrapper output: {e}")))?;

    Ok(result)
}


/// Parse nmap XML output into structured JSON.
///
/// This tool has no Cedar policy gate -- it operates on local files only.
/// It's a pure data transformation, not a privileged operation.
#[derive(Debug, Serialize, Deserialize)]
pub struct ParseNmapXmlInput {
    /// Path to the nmap XML output file
    pub output_file: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ParsedNmapOutput {
    pub scan_info: serde_json::Value,
    pub hosts_count: usize,
    pub hosts: Vec<serde_json::Value>,
}

pub fn parse_nmap_xml(input: ParseNmapXmlInput) -> Result<ParsedNmapOutput, ToolError> {
    let output = Command::new("python3")
        .arg("/app/scripts/parse-nmap-xml.py")
        .arg(&input.output_file)
        .output()
        .map_err(|e| ToolError::ExecutionFailed(format!("Parser failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::ExecutionFailed(format!("Parser error: {stderr}")));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: ParsedNmapOutput = serde_json::from_str(&stdout)
        .map_err(|e| ToolError::ParseError(format!("JSON parse error: {e}")))?;

    Ok(parsed)
}


/// Look up CVE information for a service/version combination.
///
/// Cedar-gated: requires Network.Http capability (queries external CVE API).
/// Rate limited to prevent API abuse.
#[derive(Debug, Serialize, Deserialize)]
pub struct LookupCveInput {
    /// Service name (e.g., "openssh", "apache", "nginx")
    pub service: String,

    /// Version string (e.g., "8.9p1", "2.4.57")
    pub version: String,

    /// Product name if available (e.g., "OpenSSH", "Apache httpd")
    #[serde(default)]
    pub product: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CveResult {
    pub cve_id: String,
    pub severity: String,       // critical, high, medium, low
    pub cvss_score: f32,
    pub description: String,
    pub published_date: String,
    pub references: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LookupCveOutput {
    pub query: String,
    pub cve_count: usize,
    pub cves: Vec<CveResult>,
}

pub fn lookup_cve(input: LookupCveInput) -> Result<LookupCveOutput, ToolError> {
    // In production, this queries the NVD API or a local CVE mirror.
    // For this example, we show the interface the agent uses.
    //
    // The Cedar gate for this tool checks:
    //   - principal has Network.Http capability
    //   - rate_counters.cve_lookups_1m < 30

    let query = if input.product.is_empty() {
        format!("{} {}", input.service, input.version)
    } else {
        format!("{} {} {}", input.product, input.service, input.version)
    };

    // TODO: Implement actual NVD/CVE API call
    // For now, return empty results -- the LLM will note this in its analysis
    Ok(LookupCveOutput {
        query,
        cve_count: 0,
        cves: vec![],
    })
}


// =============================================================================
// Tool registration
//
// These tools are registered with the Symbiont MCP server at startup.
// The runtime exposes them to the LLM during the REASON phase and
// intercepts invocations at the GATE phase for Cedar evaluation.
// =============================================================================

pub fn register_tools() -> Vec<Tool> {
    vec![
        Tool::new("nmap_scan")
            .description("Execute a governed nmap scan against a target. \
                          The scan type and target must comply with Cedar policies. \
                          Aggressive scans require human approval.")
            .input_schema::<NmapScanInput>()
            .cedar_resource("NmapRecon::ScanTarget")
            .cedar_actions(&[
                "NmapRecon::Action::scan",
                "NmapRecon::Action::execute_scan_type",
            ]),

        Tool::new("parse_nmap_xml")
            .description("Parse nmap XML output into structured JSON for analysis. \
                          Operates on local files only -- no policy gate required.")
            .input_schema::<ParseNmapXmlInput>()
            .no_policy_gate(),

        Tool::new("lookup_cve")
            .description("Look up known CVEs for a service/version combination. \
                          Queries external CVE databases.")
            .input_schema::<LookupCveInput>()
            .cedar_resource("NmapRecon::CveQuery")
            .cedar_actions(&["NmapRecon::Action::query_external"]),
    ]
}

// =============================================================================
// vuln_tools.rs -- MCP tool definitions for vulnerability assessment
//
// These tools are what the agent's REASON phase can propose calling during
// the vulnerability assessment stage. Each proposed tool call goes through
// the ORGA GATE before execution. The LLM sees the tool schemas; Cedar
// policies govern whether any specific invocation is permitted.
//
// Tool call flow:
//   1. LLM proposes a tool call (e.g., nmap_vuln_script, nuclei_scan)
//   2. Runtime extracts the action and builds a Cedar request
//   3. Cedar evaluates against policies/*.cedar
//   4. If ALLOW: runtime executes the tool
//   5. If DENY: runtime returns a policy denial to the LLM (no execution)
//   6. Result (or denial) feeds back into the next OBSERVE phase
//
// Registered tools:
//   - nmap_vuln_script: Nmap vulnerability script scanning
//   - nuclei_scan: Nuclei template-based vulnerability scanning
//   - sqlmap_detect: SQL injection detection (detect mode only)
//   - searchsploit_query: Offline exploit database search (no Cedar gate)
// =============================================================================

use serde::{Deserialize, Serialize};
use crate::types::{ToolDefinition, ToolError, validate_port_range, validate_nmap_scripts, validate_url};
use std::process::Command;


// =============================================================================
// nmap_vuln_script -- Nmap NSE vulnerability script scanning
// =============================================================================

/// Execute nmap with NSE vulnerability scripts against a target.
///
/// This tool is gated by Cedar policies:
///   - scan-authorization.cedar: target CIDR and scan type validation
///   - rate-limits.cedar: scan frequency enforcement
///   - escalation.cedar: human approval for vuln_script scan type
///
/// The agent CANNOT execute this tool without passing all three policy files.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NmapVulnScriptInput {
    /// Target IP address or CIDR range (must be in allowed_cidrs)
    pub target: String,

    /// Port range to scan (default "1-65535")
    #[serde(default = "default_port_range")]
    pub port_range: String,

    /// NSE script categories or names (default "vuln")
    #[serde(default = "default_scripts")]
    pub scripts: String,
}

fn default_port_range() -> String {
    "1-65535".to_string()
}

fn default_scripts() -> String {
    "vuln".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NmapVulnScriptOutput {
    pub status: String,
    pub output_file: String,
    pub scan_id: String,
    pub duration_ms: u64,
    pub tool: String,
    pub command: String,
    pub parsed_results: Option<serde_json::Value>,
}

/// MCP tool: nmap_vuln_script
///
/// Cedar resource attributes populated by the runtime before Gate evaluation:
///   - resource.cidr = input.target
///   - resource.scan_type = "vuln_script"
///   - resource.environment = looked up from target registry
///   - resource.is_external = true if target is outside RFC 1918
pub fn nmap_vuln_script(input: NmapVulnScriptInput) -> Result<NmapVulnScriptOutput, ToolError> {
    // Validate port_range and scripts to prevent injection via extra_flags
    validate_port_range(&input.port_range)?;
    validate_nmap_scripts(&input.scripts)?;

    let scan_id = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        std::process::id()
    );

    // Pass port range and scripts as separate arguments so the wrapper can
    // handle them safely. The scan_id must be the 3rd arg to match the wrapper.
    let output = Command::new("/app/scripts/tool-wrappers/nmap-wrapper.sh")
        .arg(&input.target)
        .arg("vuln_script")
        .arg(&scan_id)
        .arg(format!("-p {}", input.port_range))
        .arg(format!("--script={}", input.scripts))
        .output()
        .map_err(|e| ToolError::ExecutionFailed(format!("nmap wrapper failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::ExecutionFailed(
            format!("nmap exited with {}: {stderr}", output.status)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse the wrapper's JSON output to get the output file path
    let wrapper_result: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| ToolError::ParseError(format!("Failed to parse wrapper output: {e}")))?;

    let output_file = wrapper_result
        .get("output_file")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let duration_ms = wrapper_result
        .get("duration_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let command = wrapper_result
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Attempt to parse the nmap XML output for structured results
    let parsed_results = if !output_file.is_empty() {
        let parse_output = Command::new("python3")
            .arg("/app/scripts/parse-outputs/parse-nmap-xml.py")
            .arg(&output_file)
            .output();

        match parse_output {
            Ok(po) if po.status.success() => {
                let parse_stdout = String::from_utf8_lossy(&po.stdout);
                serde_json::from_str(&parse_stdout).ok()
            }
            _ => None,
        }
    } else {
        None
    };

    Ok(NmapVulnScriptOutput {
        status: "success".to_string(),
        output_file,
        scan_id,
        duration_ms,
        tool: "nmap_vuln_script".to_string(),
        command,
        parsed_results,
    })
}


// =============================================================================
// nuclei_scan -- Nuclei template-based vulnerability scanning
// =============================================================================

/// Execute a Nuclei vulnerability scan against a target.
///
/// Cedar-gated: requires PenTest::Action::"scan" and PenTest::Action::"execute_tool"
/// on PenTest::ScanTarget.
///
/// Nuclei runs template-based checks against the target, filtering by severity.
/// Output is JSONL format, parsed into structured findings.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NucleiScanInput {
    /// Target URL or IP address
    pub target: String,

    /// Comma-separated template IDs (empty string = all templates)
    #[serde(default)]
    pub templates: String,

    /// Comma-separated severity filter (default "critical,high,medium")
    #[serde(default = "default_severity_filter")]
    pub severity_filter: String,

    /// Rate limit in requests per second (default 150)
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u32,
}

fn default_severity_filter() -> String {
    "critical,high,medium".to_string()
}

fn default_rate_limit() -> u32 {
    150
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NucleiScanOutput {
    pub status: String,
    pub output_file: String,
    pub scan_id: String,
    pub duration_ms: u64,
    pub tool: String,
    pub command: String,
    pub parsed_results: Option<NucleiParsedResults>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NucleiParsedResults {
    pub target: String,
    pub templates_used: Vec<String>,
    pub findings_count: usize,
    pub findings: Vec<NucleiFinding>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NucleiFinding {
    pub template_id: String,
    pub name: String,
    pub severity: String,
    pub matched_at: String,
    pub description: String,
    pub reference: Vec<String>,
    pub curl_command: String,
}

pub fn nuclei_scan(input: NucleiScanInput) -> Result<NucleiScanOutput, ToolError> {
    let scan_id = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        std::process::id()
    );

    let rate_limit_str = input.rate_limit.to_string();

    let output = Command::new("/app/scripts/tool-wrappers/nuclei-wrapper.sh")
        .arg(&input.target)
        .arg(&input.templates)
        .arg(&input.severity_filter)
        .arg(&rate_limit_str)
        .arg(&scan_id)
        .output()
        .map_err(|e| ToolError::ExecutionFailed(format!("nuclei wrapper failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::ExecutionFailed(
            format!("nuclei exited with {}: {stderr}", output.status)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let wrapper_result: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| ToolError::ParseError(format!("Failed to parse wrapper output: {e}")))?;

    let output_file = wrapper_result
        .get("output_file")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let duration_ms = wrapper_result
        .get("duration_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let command = wrapper_result
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Parse the nuclei JSONL output into structured findings
    let parsed_results = if !output_file.is_empty() {
        let parse_output = Command::new("python3")
            .arg("/app/scripts/parse-outputs/parse-nuclei.py")
            .arg(&output_file)
            .arg(&input.target)
            .output();

        match parse_output {
            Ok(po) if po.status.success() => {
                let parse_stdout = String::from_utf8_lossy(&po.stdout);
                serde_json::from_str(&parse_stdout).ok()
            }
            _ => None,
        }
    } else {
        None
    };

    Ok(NucleiScanOutput {
        status: "success".to_string(),
        output_file,
        scan_id,
        duration_ms,
        tool: "nuclei_scan".to_string(),
        command,
        parsed_results,
    })
}


// =============================================================================
// sqlmap_detect -- SQL injection detection (detect mode only)
// =============================================================================

/// Detect SQL injection vulnerabilities in a target URL.
///
/// Cedar-gated: requires PenTest::Action::"scan" and PenTest::Action::"execute_tool"
/// on PenTest::ScanTarget.
///
/// This tool runs in detect mode ONLY -- it identifies injection points but
/// does NOT extract data, escalate privileges, or open OS shells. The exploit
/// mode is handled separately by exploit_tools with stricter Cedar policies.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SqlmapDetectInput {
    /// Target URL with injectable parameter (e.g., "http://target/page?id=1")
    pub target_url: String,

    /// HTTP method: GET or POST (default "GET")
    #[serde(default = "default_http_method")]
    pub method: String,

    /// POST data (optional, for POST requests)
    #[serde(default)]
    pub data: String,

    /// Detection level 1-5 (higher = more tests, default 1)
    #[serde(default = "default_level")]
    pub level: u8,

    /// Risk level 1-3 (higher = more aggressive tests, default 1)
    #[serde(default = "default_risk")]
    pub risk: u8,
}

fn default_http_method() -> String {
    "GET".to_string()
}

fn default_level() -> u8 {
    1
}

fn default_risk() -> u8 {
    1
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SqlmapDetectOutput {
    pub status: String,
    pub output_file: String,
    pub scan_id: String,
    pub duration_ms: u64,
    pub tool: String,
    pub command: String,
    pub mode: String,
    pub vulnerable: bool,
    pub parsed_results: Option<SqlmapParsedResults>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SqlmapParsedResults {
    pub target_url: String,
    pub method: String,
    pub vulnerable: bool,
    pub injection_points: Vec<SqlmapInjectionPoint>,
    pub databases: Vec<String>,
    pub tables: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SqlmapInjectionPoint {
    pub parameter: String,
    #[serde(rename = "type")]
    pub injection_type: String,
    pub title: String,
    pub payload: String,
}

pub fn sqlmap_detect(input: SqlmapDetectInput) -> Result<SqlmapDetectOutput, ToolError> {
    validate_url(&input.target_url)?;

    let scan_id = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        std::process::id()
    );

    // Clamp level and risk to valid ranges
    let level = input.level.clamp(1, 5);
    let risk = input.risk.clamp(1, 3);

    let output = Command::new("/app/scripts/tool-wrappers/sqlmap-wrapper.sh")
        .arg(&input.target_url)
        .arg(&input.method)
        .arg(&input.data)
        .arg(level.to_string())
        .arg(risk.to_string())
        .arg("detect")
        .arg(&scan_id)
        .output()
        .map_err(|e| ToolError::ExecutionFailed(format!("sqlmap wrapper failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::ExecutionFailed(
            format!("sqlmap exited with {}: {stderr}", output.status)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let wrapper_result: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| ToolError::ParseError(format!("Failed to parse wrapper output: {e}")))?;

    let output_file = wrapper_result
        .get("output_file")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let duration_ms = wrapper_result
        .get("duration_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let command = wrapper_result
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let vulnerable = wrapper_result
        .get("vulnerable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Parse the sqlmap output directory into structured findings
    let parsed_results = if !output_file.is_empty() {
        let parse_output = Command::new("python3")
            .arg("/app/scripts/parse-outputs/parse-sqlmap.py")
            .arg(&output_file)
            .arg(&input.target_url)
            .arg(&input.method)
            .output();

        match parse_output {
            Ok(po) if po.status.success() => {
                let parse_stdout = String::from_utf8_lossy(&po.stdout);
                serde_json::from_str(&parse_stdout).ok()
            }
            _ => None,
        }
    } else {
        None
    };

    Ok(SqlmapDetectOutput {
        status: "success".to_string(),
        output_file,
        scan_id,
        duration_ms,
        tool: "sqlmap_detect".to_string(),
        command,
        mode: "detect".to_string(),
        vulnerable,
        parsed_results,
    })
}


// =============================================================================
// searchsploit_query -- Offline exploit database search
// =============================================================================

/// Search the local Exploit-DB database via searchsploit.
///
/// No Cedar policy gate required -- this tool operates on a local, read-only
/// database. It does not connect to any network resources or interact with
/// any target systems.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SearchsploitQueryInput {
    /// Search terms (e.g., "apache 2.4", "openssh 8.9")
    pub query: String,

    /// If true, require exact match on all terms (default false)
    #[serde(default)]
    pub exact: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchsploitExploit {
    pub title: String,
    pub path: String,
    #[serde(rename = "type")]
    pub exploit_type: String,
    pub platform: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchsploitQueryOutput {
    pub status: String,
    pub query: String,
    pub exact: bool,
    pub scan_id: String,
    pub duration_ms: u64,
    pub tool: String,
    pub command: String,
    pub exploits_count: usize,
    pub exploits: Vec<SearchsploitExploit>,
}

pub fn searchsploit_query(input: SearchsploitQueryInput) -> Result<SearchsploitQueryOutput, ToolError> {
    let scan_id = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        std::process::id()
    );

    let exact_str = if input.exact { "true" } else { "false" };

    let output = Command::new("/app/scripts/tool-wrappers/searchsploit-wrapper.sh")
        .arg(&input.query)
        .arg(exact_str)
        .arg(&scan_id)
        .output()
        .map_err(|e| ToolError::ExecutionFailed(format!("searchsploit wrapper failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::ExecutionFailed(
            format!("searchsploit exited with {}: {stderr}", output.status)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let wrapper_result: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| ToolError::ParseError(format!("Failed to parse wrapper output: {e}")))?;

    let duration_ms = wrapper_result
        .get("duration_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let command = wrapper_result
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Parse exploits from the wrapper output
    let exploits: Vec<SearchsploitExploit> = wrapper_result
        .get("exploits")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let exploits_count = exploits.len();

    Ok(SearchsploitQueryOutput {
        status: "success".to_string(),
        query: input.query,
        exact: input.exact,
        scan_id,
        duration_ms,
        tool: "searchsploit_query".to_string(),
        command,
        exploits_count,
        exploits,
    })
}


// =============================================================================
// Tool registration
//
// These tools are registered with the Symbiont MCP server at startup.
// The runtime exposes them to the LLM during the REASON phase and
// intercepts invocations at the GATE phase for Cedar evaluation.
// =============================================================================

pub fn register_tools() -> Vec<ToolDefinition> {
    vec![
        // --- Vuln assessment tools (Cedar-gated) ---
        ToolDefinition::new("nmap_vuln_script")
            .description("Execute nmap with NSE vulnerability scripts against a target. \
                          Scans the specified port range and runs the given NSE scripts \
                          (default: vuln category). Requires human approval via Cedar.")
            .input_schema::<NmapVulnScriptInput>()
            .cedar_resource("PenTest::ScanTarget")
            .cedar_actions(&[
                "PenTest::Action::\"scan\"",
                "PenTest::Action::\"execute_tool\"",
            ]),

        ToolDefinition::new("nuclei_scan")
            .description("Run Nuclei template-based vulnerability scanner against a target. \
                          Filters by severity level and supports specific template selection. \
                          Returns structured findings with template IDs and descriptions.")
            .input_schema::<NucleiScanInput>()
            .cedar_resource("PenTest::ScanTarget")
            .cedar_actions(&[
                "PenTest::Action::\"scan\"",
                "PenTest::Action::\"execute_tool\"",
            ]),

        ToolDefinition::new("sqlmap_detect")
            .description("Detect SQL injection vulnerabilities in a target URL. \
                          Detection mode only -- identifies injectable parameters \
                          without extracting data or escalating privileges.")
            .input_schema::<SqlmapDetectInput>()
            .cedar_resource("PenTest::ScanTarget")
            .cedar_actions(&[
                "PenTest::Action::\"scan\"",
                "PenTest::Action::\"execute_tool\"",
            ]),

        // --- Offline tools (no Cedar gate) ---
        ToolDefinition::new("searchsploit_query")
            .description("Search the local Exploit-DB database for known exploits. \
                          Offline, read-only operation. Returns matching exploits \
                          with title, path, type, and platform.")
            .input_schema::<SearchsploitQueryInput>()
            .no_policy_gate(),
    ]
}

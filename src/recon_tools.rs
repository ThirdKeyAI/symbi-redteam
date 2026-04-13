// =============================================================================
// recon_tools.rs -- MCP tool definitions for the reconnaissance agent
//
// These tools are what the agent's REASON phase can propose calling.
// Each proposed tool call goes through the ORGA GATE before execution.
// The LLM sees the tool schemas; Cedar policies govern whether any
// specific invocation is permitted.
//
// Tool call flow:
//   1. LLM proposes a tool call (e.g., nmap_scan, whois_lookup, dns_enumerate)
//   2. Runtime extracts the action and builds a Cedar request
//   3. Cedar evaluates against policies/*.cedar
//   4. If ALLOW: runtime executes the tool
//   5. If DENY: runtime returns a policy denial to the LLM (no execution)
//   6. Result (or denial) feeds back into the next OBSERVE phase
//
// Registered tools:
//   - nmap_scan: Network port scanning and service detection
//   - whois_lookup: WHOIS registration data lookup
//   - dns_enumerate: DNS record enumeration
//   - whatweb_scan: Web technology fingerprinting
//   - amass_enum: Subdomain enumeration via OWASP Amass
//   - parse_nmap_xml: Parse nmap XML output (no Cedar gate)
//   - lookup_cve: CVE database lookup for service/version combos
// =============================================================================

use serde::{Deserialize, Serialize};
use crate::types::{ToolDefinition, ToolError, validate_allowlist, validate_confined_path};
use std::process::Command;


// =============================================================================
// nmap_scan -- Network port scanning and service detection
// =============================================================================

/// Execute an nmap scan against a target.
///
/// This tool is gated by Cedar policies:
///   - scan-authorization.cedar: target CIDR and scan type validation
///   - rate-limits.cedar: scan frequency enforcement
///   - escalation.cedar: human approval for high-risk scan types
///
/// The agent CANNOT execute this tool without passing all three policy files.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NmapScanInput {
    /// Target IP address or CIDR range (must be in allowed_cidrs)
    pub target: String,

    /// Scan type: ping, service, version, syn, os_detect, aggressive, vuln_script
    pub scan_type: String,

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
    pub tool: String,
    pub command: String,
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
    validate_allowlist(
        &input.scan_type, "scan_type",
        &["ping", "service", "version", "syn", "os_detect", "aggressive", "vuln_script"],
    )?;

    let scan_id = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        std::process::id()
    );

    let output = Command::new("/app/scripts/tool-wrappers/nmap-wrapper.sh")
        .arg(&input.target)
        .arg(&input.scan_type)
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


// =============================================================================
// whois_lookup -- WHOIS registration data lookup
// =============================================================================

/// Perform a WHOIS lookup for a target IP or domain.
///
/// Cedar-gated: requires PenTest::Action::"scan" on PenTest::ScanTarget.
/// Retrieves domain/IP registration information including registrar,
/// creation/expiration dates, name servers, and contact details.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct WhoisLookupInput {
    /// Target IP address or domain name
    pub target: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WhoisLookupOutput {
    pub status: String,
    pub output_file: String,
    pub scan_id: String,
    pub duration_ms: u64,
    pub tool: String,
    pub command: String,
}

pub fn whois_lookup(input: WhoisLookupInput) -> Result<WhoisLookupOutput, ToolError> {
    let scan_id = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        std::process::id()
    );

    let output = Command::new("/app/scripts/tool-wrappers/whois-wrapper.sh")
        .arg(&input.target)
        .arg(&scan_id)
        .output()
        .map_err(|e| ToolError::ExecutionFailed(format!("whois wrapper failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::ExecutionFailed(
            format!("whois exited with {}: {stderr}", output.status)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: WhoisLookupOutput = serde_json::from_str(&stdout)
        .map_err(|e| ToolError::ParseError(format!("Failed to parse wrapper output: {e}")))?;

    Ok(result)
}


// =============================================================================
// dns_enumerate -- DNS record enumeration
// =============================================================================

/// Enumerate DNS records for a target domain.
///
/// Cedar-gated: requires PenTest::Action::"scan" on PenTest::ScanTarget.
/// Uses dig and host to resolve DNS records of the specified type.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DnsEnumerateInput {
    /// Target domain name
    pub target: String,

    /// DNS record type: A, AAAA, MX, NS, TXT, ANY, SOA, CNAME, PTR, SRV
    #[serde(default = "default_record_type")]
    pub record_type: String,
}

fn default_record_type() -> String {
    "A".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsEnumerateOutput {
    pub status: String,
    pub output_file: String,
    pub scan_id: String,
    pub duration_ms: u64,
    pub tool: String,
    pub command: String,
}

pub fn dns_enumerate(input: DnsEnumerateInput) -> Result<DnsEnumerateOutput, ToolError> {
    let scan_id = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        std::process::id()
    );

    let output = Command::new("/app/scripts/tool-wrappers/dns-wrapper.sh")
        .arg(&input.target)
        .arg(&input.record_type)
        .arg(&scan_id)
        .output()
        .map_err(|e| ToolError::ExecutionFailed(format!("dns wrapper failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::ExecutionFailed(
            format!("dns enumeration exited with {}: {stderr}", output.status)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: DnsEnumerateOutput = serde_json::from_str(&stdout)
        .map_err(|e| ToolError::ParseError(format!("Failed to parse wrapper output: {e}")))?;

    Ok(result)
}


// =============================================================================
// whatweb_scan -- Web technology fingerprinting
// =============================================================================

/// Perform web technology fingerprinting against a target URL.
///
/// Cedar-gated: requires PenTest::Action::"scan" on PenTest::ScanTarget.
/// Identifies web technologies, frameworks, CMS platforms, server software,
/// and other components running on the target.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct WhatwebScanInput {
    /// Target URL (e.g., "https://example.com")
    pub target: String,

    /// Aggression level 1-4 (1=stealthy, 4=heavy; default 1)
    #[serde(default = "default_aggression_level")]
    pub aggression_level: u8,
}

fn default_aggression_level() -> u8 {
    1
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WhatwebScanOutput {
    pub status: String,
    pub output_file: String,
    pub scan_id: String,
    pub duration_ms: u64,
    pub tool: String,
    pub command: String,
}

pub fn whatweb_scan(input: WhatwebScanInput) -> Result<WhatwebScanOutput, ToolError> {
    let scan_id = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        std::process::id()
    );

    // Clamp aggression level to valid range
    let aggression = input.aggression_level.clamp(1, 4);

    let output = Command::new("/app/scripts/tool-wrappers/whatweb-wrapper.sh")
        .arg(&input.target)
        .arg(aggression.to_string())
        .arg(&scan_id)
        .output()
        .map_err(|e| ToolError::ExecutionFailed(format!("whatweb wrapper failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::ExecutionFailed(
            format!("whatweb exited with {}: {stderr}", output.status)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: WhatwebScanOutput = serde_json::from_str(&stdout)
        .map_err(|e| ToolError::ParseError(format!("Failed to parse wrapper output: {e}")))?;

    Ok(result)
}


// =============================================================================
// amass_enum -- Subdomain enumeration via OWASP Amass
// =============================================================================

/// Enumerate subdomains for a target domain using OWASP Amass.
///
/// Cedar-gated: requires PenTest::Action::"scan" on PenTest::ScanTarget.
/// Discovers subdomains through passive data sources (default) or active
/// DNS brute-forcing when passive_only is false.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AmassEnumInput {
    /// Target domain name (e.g., "example.com")
    pub target: String,

    /// If true, only use passive data sources (default true)
    #[serde(default = "default_passive_only")]
    pub passive_only: bool,
}

fn default_passive_only() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AmassEnumOutput {
    pub status: String,
    pub output_file: String,
    pub scan_id: String,
    pub duration_ms: u64,
    pub tool: String,
    pub command: String,
}

pub fn amass_enum(input: AmassEnumInput) -> Result<AmassEnumOutput, ToolError> {
    let scan_id = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        std::process::id()
    );

    let passive_str = if input.passive_only { "true" } else { "false" };

    let output = Command::new("/app/scripts/tool-wrappers/amass-wrapper.sh")
        .arg(&input.target)
        .arg(passive_str)
        .arg(&scan_id)
        .output()
        .map_err(|e| ToolError::ExecutionFailed(format!("amass wrapper failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::ExecutionFailed(
            format!("amass exited with {}: {stderr}", output.status)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: AmassEnumOutput = serde_json::from_str(&stdout)
        .map_err(|e| ToolError::ParseError(format!("Failed to parse wrapper output: {e}")))?;

    Ok(result)
}


// =============================================================================
// parse_nmap_xml -- Parse nmap XML output into structured JSON
// =============================================================================

/// Parse nmap XML output into structured JSON.
///
/// This tool has no Cedar policy gate -- it operates on local files only.
/// It's a pure data transformation, not a privileged operation.
#[derive(Debug, Default, Serialize, Deserialize)]
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
    let safe_path = validate_confined_path(&input.output_file, "/app/.symbiont/scans/")?;

    let output = Command::new("python3")
        .arg("/app/scripts/parse-outputs/parse-nmap-xml.py")
        .arg(&safe_path)
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


// =============================================================================
// lookup_cve -- CVE database lookup for service/version combinations
// =============================================================================

/// Look up CVE information for a service/version combination.
///
/// Cedar-gated: requires Network.Http capability (queries external CVE API).
/// Rate limited to prevent API abuse.
#[derive(Debug, Default, Serialize, Deserialize)]
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
    // The Cedar gate for this tool checks:
    //   - principal has Network.Http capability
    //   - rate_counters.cve_lookups_1m < 30

    let query = if input.product.is_empty() {
        format!("{} {}", input.service, input.version)
    } else {
        format!("{} {} {}", input.product, input.service, input.version)
    };

    // Query the NVD API via the CVE lookup service
    let output = Command::new("curl")
        .args([
            "--silent",
            "--fail",
            "--max-time", "15",
            "--header", "Accept: application/json",
            &format!(
                "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}",
                urlencoding_encode(&query)
            ),
        ])
        .output()
        .map_err(|e| ToolError::ExecutionFailed(format!("CVE lookup failed: {e}")))?;

    if !output.status.success() {
        // Return empty results on API failure rather than hard-erroring;
        // the LLM will note the lookup failed in its analysis and can retry.
        return Ok(LookupCveOutput {
            query,
            cve_count: 0,
            cves: vec![],
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let api_response: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| ToolError::ParseError(format!("CVE API JSON parse error: {e}")))?;

    let mut cves = Vec::new();

    if let Some(vulnerabilities) = api_response.get("vulnerabilities").and_then(|v| v.as_array()) {
        for vuln_wrapper in vulnerabilities.iter().take(20) {
            if let Some(cve_item) = vuln_wrapper.get("cve") {
                let cve_id = cve_item
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let description = cve_item
                    .get("descriptions")
                    .and_then(|d| d.as_array())
                    .and_then(|arr| arr.iter().find(|d| {
                        d.get("lang").and_then(|l| l.as_str()) == Some("en")
                    }))
                    .and_then(|d| d.get("value"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let published_date = cve_item
                    .get("published")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                // Extract CVSS score and severity from metrics
                let (cvss_score, severity) = extract_cvss_metrics(cve_item);

                let references: Vec<String> = cve_item
                    .get("references")
                    .and_then(|r| r.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|r| r.get("url").and_then(|u| u.as_str()).map(String::from))
                            .take(5)
                            .collect()
                    })
                    .unwrap_or_default();

                cves.push(CveResult {
                    cve_id,
                    severity,
                    cvss_score,
                    description,
                    published_date,
                    references,
                });
            }
        }
    }

    let cve_count = cves.len();

    Ok(LookupCveOutput {
        query,
        cve_count,
        cves,
    })
}

/// Extract CVSS score and severity from NVD API CVE metrics.
/// Tries CVSSv3.1 first, falls back to CVSSv3.0, then CVSSv2.
fn extract_cvss_metrics(cve_item: &serde_json::Value) -> (f32, String) {
    let metrics = match cve_item.get("metrics") {
        Some(m) => m,
        None => return (0.0, "unknown".to_string()),
    };

    // Try CVSS v3.1
    if let Some(v31_arr) = metrics.get("cvssMetricV31").and_then(|v| v.as_array()) {
        if let Some(first) = v31_arr.first() {
            if let Some(cvss_data) = first.get("cvssData") {
                let score = cvss_data.get("baseScore")
                    .and_then(|s| s.as_f64())
                    .unwrap_or(0.0) as f32;
                let severity = cvss_data
                    .get("baseSeverity")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown")
                    .to_lowercase();
                return (score, severity);
            }
        }
    }

    // Try CVSS v3.0
    if let Some(v30_arr) = metrics.get("cvssMetricV30").and_then(|v| v.as_array()) {
        if let Some(first) = v30_arr.first() {
            if let Some(cvss_data) = first.get("cvssData") {
                let score = cvss_data.get("baseScore")
                    .and_then(|s| s.as_f64())
                    .unwrap_or(0.0) as f32;
                let severity = cvss_data
                    .get("baseSeverity")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown")
                    .to_lowercase();
                return (score, severity);
            }
        }
    }

    // Try CVSS v2
    if let Some(v2_arr) = metrics.get("cvssMetricV2").and_then(|v| v.as_array()) {
        if let Some(first) = v2_arr.first() {
            if let Some(cvss_data) = first.get("cvssData") {
                let score = cvss_data.get("baseScore")
                    .and_then(|s| s.as_f64())
                    .unwrap_or(0.0) as f32;
                let severity = first
                    .get("baseSeverity")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown")
                    .to_lowercase();
                return (score, severity);
            }
        }
    }

    (0.0, "unknown".to_string())
}

/// Minimal URL-encoding for the CVE query string.
/// Encodes spaces and special characters that would break the URL.
fn urlencoding_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            b' ' => {
                encoded.push_str("%20");
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
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
        // --- Recon tools (Cedar-gated) ---
        ToolDefinition::new("nmap_scan")
            .description("Execute a governed nmap scan against a target. \
                          The scan type and target must comply with Cedar policies. \
                          Aggressive scans require human approval.")
            .input_schema::<NmapScanInput>()
            .cedar_resource("PenTest::ScanTarget")
            .cedar_actions(&[
                "PenTest::Action::\"scan\"",
                "PenTest::Action::\"execute_tool\"",
            ]),

        ToolDefinition::new("whois_lookup")
            .description("Perform a WHOIS lookup for a target IP or domain. \
                          Returns registration data including registrar, dates, \
                          name servers, and contact information.")
            .input_schema::<WhoisLookupInput>()
            .cedar_resource("PenTest::ScanTarget")
            .cedar_actions(&[
                "PenTest::Action::\"scan\"",
            ]),

        ToolDefinition::new("dns_enumerate")
            .description("Enumerate DNS records for a target domain. \
                          Supports A, AAAA, MX, NS, TXT, ANY, and other record types. \
                          Uses dig and host for comprehensive resolution.")
            .input_schema::<DnsEnumerateInput>()
            .cedar_resource("PenTest::ScanTarget")
            .cedar_actions(&[
                "PenTest::Action::\"scan\"",
            ]),

        ToolDefinition::new("whatweb_scan")
            .description("Fingerprint web technologies on a target URL. \
                          Identifies CMS, frameworks, server software, and plugins. \
                          Aggression level 1 is stealthy, 4 is heavy.")
            .input_schema::<WhatwebScanInput>()
            .cedar_resource("PenTest::ScanTarget")
            .cedar_actions(&[
                "PenTest::Action::\"scan\"",
            ]),

        ToolDefinition::new("amass_enum")
            .description("Enumerate subdomains for a target domain using OWASP Amass. \
                          Passive mode uses public data sources only. \
                          Active mode includes DNS brute-forcing.")
            .input_schema::<AmassEnumInput>()
            .cedar_resource("PenTest::ScanTarget")
            .cedar_actions(&[
                "PenTest::Action::\"scan\"",
            ]),

        // --- Parser tools (no Cedar gate) ---
        ToolDefinition::new("parse_nmap_xml")
            .description("Parse nmap XML output into structured JSON for analysis. \
                          Operates on local files only -- no policy gate required.")
            .input_schema::<ParseNmapXmlInput>()
            .no_policy_gate(),

        // --- External query tools (Cedar-gated) ---
        ToolDefinition::new("lookup_cve")
            .description("Look up known CVEs for a service/version combination. \
                          Queries the NVD API and returns matching vulnerabilities \
                          with CVSS scores and severity ratings.")
            .input_schema::<LookupCveInput>()
            .cedar_resource("PenTest::CveQuery")
            .cedar_actions(&["PenTest::Action::\"query_external\""]),
    ]
}

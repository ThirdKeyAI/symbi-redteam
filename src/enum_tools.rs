// =============================================================================
// enum_tools.rs -- MCP tool definitions for the enumeration agent
//
// These tools are what the agent's REASON phase can propose calling.
// Each proposed tool call goes through the ORGA GATE before execution.
// The LLM sees the tool schemas; Cedar policies govern whether any
// specific invocation is permitted.
//
// Tool call flow:
//   1. LLM proposes: nikto_scan(target="http://10.0.1.5", tuning="1")
//   2. Runtime extracts the action and builds a Cedar request
//   3. Cedar evaluates against policies/*.cedar
//   4. If ALLOW: runtime executes the tool
//   5. If DENY: runtime returns a policy denial to the LLM (no execution)
//   6. Result (or denial) feeds back into the next OBSERVE phase
// =============================================================================

use serde::{Deserialize, Serialize};
use std::process::Command;
use crate::types::{ToolDefinition, ToolError, validate_allowlist, validate_confined_path, validate_url};

// =============================================================================
// nikto_scan
// =============================================================================

/// Execute a Nikto web vulnerability scan against a target URL.
///
/// This tool is gated by Cedar policies:
///   - resource: PenTest::ScanTarget
///   - actions: PenTest::Action::"scan", PenTest::Action::"execute_tool"
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NiktoScanInput {
    /// Target URL (e.g., "http://10.0.1.5" or "https://target.local:8443")
    pub target: String,

    /// Nikto tuning option (1-9), controls which tests to run.
    /// 0 = all tests (default).
    /// 1=Interesting File, 2=Misconfiguration, 3=Information Disclosure,
    /// 4=Injection (XSS/Script/HTML), 5=Remote File Retrieval (Inside Web Root),
    /// 6=Denial of Service, 7=Remote File Retrieval (Server Wide),
    /// 8=Command Execution / Remote Shell, 9=SQL Injection
    #[serde(default = "default_nikto_tuning")]
    pub tuning: String,

    /// Output format: "json" (default) or "xml"
    #[serde(default = "default_nikto_output_format")]
    pub output_format: String,
}

fn default_nikto_tuning() -> String {
    "0".to_string()
}

fn default_nikto_output_format() -> String {
    "json".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NiktoScanOutput {
    pub status: String,
    pub output_file: String,
    pub scan_id: String,
    pub duration_ms: u64,
    pub tool: String,
    pub command: String,
}

/// MCP tool: nikto_scan
///
/// Cedar resource attributes populated by the runtime before Gate evaluation:
///   - resource.target = input.target
///   - resource.tuning = input.tuning
pub fn nikto_scan(input: NiktoScanInput) -> Result<NiktoScanOutput, ToolError> {
    validate_url(&input.target)?;

    let scan_id = format!(
        "nikto-{}-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        std::process::id()
    );

    let output = Command::new("/app/scripts/tool-wrappers/nikto-wrapper.sh")
        .arg(&input.target)
        .arg(&input.tuning)
        .arg(&input.output_format)
        .arg(&scan_id)
        .output()
        .map_err(|e| ToolError::ExecutionFailed(format!("nikto wrapper failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::ExecutionFailed(format!(
            "nikto exited with {}: {stderr}",
            output.status
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: NiktoScanOutput = serde_json::from_str(&stdout)
        .map_err(|e| ToolError::ParseError(format!("Failed to parse wrapper output: {e}")))?;

    Ok(result)
}

// =============================================================================
// gobuster_scan
// =============================================================================

/// Execute a Gobuster directory/DNS/vhost brute-force scan.
///
/// This tool is gated by Cedar policies:
///   - resource: PenTest::ScanTarget
///   - actions: PenTest::Action::"scan", PenTest::Action::"execute_tool"
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GobusterScanInput {
    /// Target URL (e.g., "http://10.0.1.5")
    pub target: String,

    /// Scan mode: "dir" (directory brute-force), "dns" (subdomain enum),
    /// "vhost" (virtual host discovery). Default: "dir"
    #[serde(default = "default_gobuster_mode")]
    pub mode: String,

    /// Path to the wordlist file. Default: /usr/share/wordlists/dirb/common.txt
    #[serde(default = "default_gobuster_wordlist")]
    pub wordlist: String,

    /// Comma-separated file extensions to check (dir mode). Default: "php,html,txt"
    #[serde(default = "default_gobuster_extensions")]
    pub extensions: String,
}

fn default_gobuster_mode() -> String {
    "dir".to_string()
}

fn default_gobuster_wordlist() -> String {
    "/usr/share/wordlists/dirb/common.txt".to_string()
}

fn default_gobuster_extensions() -> String {
    "php,html,txt".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GobusterScanOutput {
    pub status: String,
    pub output_file: String,
    pub scan_id: String,
    pub duration_ms: u64,
    pub tool: String,
    pub command: String,
}

/// MCP tool: gobuster_scan
///
/// Cedar resource attributes populated by the runtime before Gate evaluation:
///   - resource.target = input.target
///   - resource.mode = input.mode
pub fn gobuster_scan(input: GobusterScanInput) -> Result<GobusterScanOutput, ToolError> {
    validate_allowlist(&input.mode, "mode", &["dir", "dns", "vhost"])?;
    validate_url(&input.target)?;
    // Confine wordlists to known safe directories
    validate_confined_path(&input.wordlist, "/usr/share/")?;

    let scan_id = format!(
        "gobuster-{}-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        std::process::id()
    );

    let output = Command::new("/app/scripts/tool-wrappers/gobuster-wrapper.sh")
        .arg(&input.target)
        .arg(&input.mode)
        .arg(&input.wordlist)
        .arg(&input.extensions)
        .arg(&scan_id)
        .output()
        .map_err(|e| ToolError::ExecutionFailed(format!("gobuster wrapper failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::ExecutionFailed(format!(
            "gobuster exited with {}: {stderr}",
            output.status
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: GobusterScanOutput = serde_json::from_str(&stdout)
        .map_err(|e| ToolError::ParseError(format!("Failed to parse wrapper output: {e}")))?;

    Ok(result)
}

// =============================================================================
// enum4linux_scan
// =============================================================================

/// Execute an enum4linux scan for SMB/NetBIOS enumeration.
///
/// This tool is gated by Cedar policies:
///   - resource: PenTest::ScanTarget
///   - actions: PenTest::Action::"scan", PenTest::Action::"execute_tool"
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Enum4linuxScanInput {
    /// Target IP address (e.g., "10.0.1.5")
    pub target: String,

    /// Scan type: all, users, shares, policies, groups
    /// Maps to the wrapper's enum: all=-a, users=-U, shares=-S, policies=-P, groups=-G
    #[serde(default = "default_enum4linux_scan_type")]
    pub scan_type: String,
}

fn default_enum4linux_scan_type() -> String {
    "all".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Enum4linuxScanOutput {
    pub status: String,
    pub output_file: String,
    pub scan_id: String,
    pub duration_ms: u64,
    pub tool: String,
    pub command: String,
}

/// MCP tool: enum4linux_scan
///
/// Cedar resource attributes populated by the runtime before Gate evaluation:
///   - resource.target = input.target
///   - resource.options = input.options
pub fn enum4linux_scan(input: Enum4linuxScanInput) -> Result<Enum4linuxScanOutput, ToolError> {
    validate_allowlist(
        &input.scan_type, "scan_type",
        &["all", "users", "shares", "policies", "groups"],
    )?;

    let scan_id = format!(
        "enum4linux-{}-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        std::process::id()
    );

    let output = Command::new("/app/scripts/tool-wrappers/enum4linux-wrapper.sh")
        .arg(&input.target)
        .arg(&input.scan_type)
        .arg(&scan_id)
        .output()
        .map_err(|e| ToolError::ExecutionFailed(format!("enum4linux wrapper failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::ExecutionFailed(format!(
            "enum4linux exited with {}: {stderr}",
            output.status
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: Enum4linuxScanOutput = serde_json::from_str(&stdout)
        .map_err(|e| ToolError::ParseError(format!("Failed to parse wrapper output: {e}")))?;

    Ok(result)
}

// =============================================================================
// smbclient_access
// =============================================================================

/// Access or enumerate SMB shares on a target using smbclient.
///
/// This tool is gated by Cedar policies:
///   - resource: PenTest::ScanTarget
///   - actions: PenTest::Action::"scan", PenTest::Action::"execute_tool"
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SmbclientAccessInput {
    /// Target IP address (e.g., "10.0.1.5")
    pub target: String,

    /// Share name to connect to. If empty, lists all available shares.
    #[serde(default)]
    pub share: String,

    /// Username for authentication. Default: anonymous (empty)
    #[serde(default)]
    pub username: String,

    /// Password for authentication. Default: empty (anonymous)
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SmbclientAccessOutput {
    pub status: String,
    pub output_file: String,
    pub scan_id: String,
    pub duration_ms: u64,
    pub tool: String,
    pub command: String,
}

/// MCP tool: smbclient_access
///
/// Cedar resource attributes populated by the runtime before Gate evaluation:
///   - resource.target = input.target
///   - resource.share = input.share
///   - resource.is_anonymous = true if username is empty
pub fn smbclient_access(input: SmbclientAccessInput) -> Result<SmbclientAccessOutput, ToolError> {
    let scan_id = format!(
        "smbclient-{}-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        std::process::id()
    );

    let output = Command::new("/app/scripts/tool-wrappers/smbclient-wrapper.sh")
        .arg(&input.target)
        .arg(&input.share)
        .arg(&input.username)
        .arg(&input.password)
        .arg(&scan_id)
        .output()
        .map_err(|e| ToolError::ExecutionFailed(format!("smbclient wrapper failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::ExecutionFailed(format!(
            "smbclient exited with {}: {stderr}",
            output.status
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: SmbclientAccessOutput = serde_json::from_str(&stdout)
        .map_err(|e| ToolError::ParseError(format!("Failed to parse wrapper output: {e}")))?;

    Ok(result)
}

// =============================================================================
// snmpwalk_enum
// =============================================================================

/// Enumerate SNMP information on a target using snmpwalk.
///
/// This tool is gated by Cedar policies:
///   - resource: PenTest::ScanTarget
///   - actions: PenTest::Action::"scan", PenTest::Action::"execute_tool"
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SnmpwalkEnumInput {
    /// Target IP address (e.g., "10.0.1.5")
    pub target: String,

    /// SNMP community string. Default: "public"
    #[serde(default = "default_snmp_community")]
    pub community: String,

    /// SNMP version: "1", "2c", or "3". Default: "2c"
    #[serde(default = "default_snmp_version")]
    pub version: String,

    /// OID to start walking from. Empty = walk entire tree.
    #[serde(default)]
    pub oid: String,
}

fn default_snmp_community() -> String {
    "public".to_string()
}

fn default_snmp_version() -> String {
    "2c".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnmpwalkEnumOutput {
    pub status: String,
    pub output_file: String,
    pub scan_id: String,
    pub duration_ms: u64,
    pub tool: String,
    pub command: String,
}

/// MCP tool: snmpwalk_enum
///
/// Cedar resource attributes populated by the runtime before Gate evaluation:
///   - resource.target = input.target
///   - resource.community = input.community
///   - resource.version = input.version
pub fn snmpwalk_enum(input: SnmpwalkEnumInput) -> Result<SnmpwalkEnumOutput, ToolError> {
    let scan_id = format!(
        "snmpwalk-{}-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        std::process::id()
    );

    let output = Command::new("/app/scripts/tool-wrappers/snmpwalk-wrapper.sh")
        .arg(&input.target)
        .arg(&input.community)
        .arg(&input.version)
        .arg(&input.oid)
        .arg(&scan_id)
        .output()
        .map_err(|e| ToolError::ExecutionFailed(format!("snmpwalk wrapper failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::ExecutionFailed(format!(
            "snmpwalk exited with {}: {stderr}",
            output.status
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: SnmpwalkEnumOutput = serde_json::from_str(&stdout)
        .map_err(|e| ToolError::ParseError(format!("Failed to parse wrapper output: {e}")))?;

    Ok(result)
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
        ToolDefinition::new("nikto_scan")
            .description(
                "Execute a governed Nikto web vulnerability scan against a target URL. \
                 Nikto checks for dangerous files, outdated server software, and \
                 version-specific vulnerabilities. Tuning parameter controls test categories.",
            )
            .input_schema::<NiktoScanInput>()
            .cedar_resource("PenTest::ScanTarget")
            .cedar_actions(&[
                "PenTest::Action::\"scan\"",
                "PenTest::Action::\"execute_tool\"",
            ]),
        ToolDefinition::new("gobuster_scan")
            .description(
                "Execute a governed Gobuster scan for directory/file brute-forcing, \
                 subdomain enumeration, or virtual host discovery. Uses wordlist-based \
                 approach to find hidden content on web servers.",
            )
            .input_schema::<GobusterScanInput>()
            .cedar_resource("PenTest::ScanTarget")
            .cedar_actions(&[
                "PenTest::Action::\"scan\"",
                "PenTest::Action::\"execute_tool\"",
            ]),
        ToolDefinition::new("enum4linux_scan")
            .description(
                "Execute a governed enum4linux scan for SMB/NetBIOS enumeration. \
                 Enumerates users, shares, groups, password policies, and OS information \
                 from Windows/Samba systems via SMB and RPC.",
            )
            .input_schema::<Enum4linuxScanInput>()
            .cedar_resource("PenTest::ScanTarget")
            .cedar_actions(&[
                "PenTest::Action::\"scan\"",
                "PenTest::Action::\"execute_tool\"",
            ]),
        ToolDefinition::new("smbclient_access")
            .description(
                "Access or enumerate SMB shares on a target using smbclient. \
                 Can list available shares (anonymous or authenticated) or browse \
                 contents of a specific share.",
            )
            .input_schema::<SmbclientAccessInput>()
            .cedar_resource("PenTest::ScanTarget")
            .cedar_actions(&[
                "PenTest::Action::\"scan\"",
                "PenTest::Action::\"execute_tool\"",
            ]),
        ToolDefinition::new("snmpwalk_enum")
            .description(
                "Execute a governed SNMP walk against a target to enumerate system \
                 information, network interfaces, running processes, and installed \
                 software via SNMP. Supports v1, v2c, and v3.",
            )
            .input_schema::<SnmpwalkEnumInput>()
            .cedar_resource("PenTest::ScanTarget")
            .cedar_actions(&[
                "PenTest::Action::\"scan\"",
                "PenTest::Action::\"execute_tool\"",
            ]),
    ]
}

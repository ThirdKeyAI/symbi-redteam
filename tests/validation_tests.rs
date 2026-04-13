use symbi_redteam::types::*;

// =============================================================================
// validate_engagement_id
// =============================================================================

#[test]
fn engagement_id_valid_uuid() {
    assert!(validate_engagement_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
}

#[test]
fn engagement_id_valid_eng_prefix() {
    assert!(validate_engagement_id("eng-demo-001").is_ok());
}

#[test]
fn engagement_id_rejects_traversal() {
    assert!(validate_engagement_id("../../../etc").is_err());
}

#[test]
fn engagement_id_rejects_empty() {
    assert!(validate_engagement_id("").is_err());
}

#[test]
fn engagement_id_rejects_slashes() {
    assert!(validate_engagement_id("eng/../../root").is_err());
}

#[test]
fn engagement_id_rejects_spaces() {
    assert!(validate_engagement_id("eng demo 001").is_err());
}

#[test]
fn engagement_id_rejects_shell_chars() {
    assert!(validate_engagement_id("eng;rm -rf /").is_err());
}

// =============================================================================
// validate_confined_path
// =============================================================================

#[test]
fn confined_path_rejects_traversal() {
    assert!(validate_confined_path("/app/.symbiont/scans/../../etc/passwd", "/app/.symbiont/").is_err());
}

#[test]
fn confined_path_rejects_wrong_prefix() {
    assert!(validate_confined_path("/etc/shadow", "/app/.symbiont/").is_err());
}

#[test]
fn confined_path_accepts_valid() {
    assert!(validate_confined_path("/app/.symbiont/scans/test.xml", "/app/.symbiont/scans/").is_ok());
}

// =============================================================================
// validate_allowlist
// =============================================================================

#[test]
fn allowlist_accepts_valid() {
    assert!(validate_allowlist("ping", "scan_type", &["ping", "service", "syn"]).is_ok());
}

#[test]
fn allowlist_rejects_invalid() {
    let result = validate_allowlist("exploit", "scan_type", &["ping", "service", "syn"]);
    assert!(result.is_err());
}

// =============================================================================
// validate_port_range
// =============================================================================

#[test]
fn port_range_valid_single() {
    assert!(validate_port_range("80").is_ok());
}

#[test]
fn port_range_valid_range() {
    assert!(validate_port_range("1-1024").is_ok());
}

#[test]
fn port_range_valid_list() {
    assert!(validate_port_range("22,80,443,8080-8090").is_ok());
}

#[test]
fn port_range_rejects_letters() {
    assert!(validate_port_range("80,http").is_err());
}

#[test]
fn port_range_rejects_shell_injection() {
    assert!(validate_port_range("80;rm -rf /").is_err());
}

#[test]
fn port_range_rejects_empty() {
    assert!(validate_port_range("").is_err());
}

// =============================================================================
// validate_nmap_scripts
// =============================================================================

#[test]
fn nmap_scripts_valid_single() {
    assert!(validate_nmap_scripts("vuln").is_ok());
}

#[test]
fn nmap_scripts_valid_list() {
    assert!(validate_nmap_scripts("http-vuln-cve2017-5638,smb-vuln-ms17-010").is_ok());
}

#[test]
fn nmap_scripts_valid_wildcard() {
    assert!(validate_nmap_scripts("http-*").is_ok());
}

#[test]
fn nmap_scripts_rejects_shell_chars() {
    assert!(validate_nmap_scripts("vuln;rm -rf /").is_err());
}

#[test]
fn nmap_scripts_rejects_path_traversal() {
    assert!(validate_nmap_scripts("../../etc/passwd").is_err());
}

// =============================================================================
// validate_url
// =============================================================================

#[test]
fn url_valid_http() {
    assert!(validate_url("http://10.0.1.5:8080/login").is_ok());
}

#[test]
fn url_valid_https() {
    assert!(validate_url("https://target.example.com/api").is_ok());
}

#[test]
fn url_rejects_semicolon() {
    assert!(validate_url("http://target.com;rm -rf /").is_err());
}

#[test]
fn url_rejects_pipe() {
    assert!(validate_url("http://target.com|cat /etc/passwd").is_err());
}

#[test]
fn url_rejects_backtick() {
    assert!(validate_url("http://target.com`whoami`").is_err());
}

#[test]
fn url_rejects_newline() {
    assert!(validate_url("http://target.com\nHost: evil.com").is_err());
}

#[test]
fn url_rejects_empty() {
    assert!(validate_url("").is_err());
}

// =============================================================================
// validate_safe_identifier
// =============================================================================

#[test]
fn safe_id_valid() {
    assert!(validate_safe_identifier("nmap-scan_v2.0", "tool_name").is_ok());
}

#[test]
fn safe_id_rejects_traversal() {
    assert!(validate_safe_identifier("../../etc", "tool_name").is_err());
}

#[test]
fn safe_id_rejects_spaces() {
    assert!(validate_safe_identifier("rm -rf /", "tool_name").is_err());
}

#[test]
fn safe_id_rejects_empty() {
    assert!(validate_safe_identifier("", "tool_name").is_err());
}

// =============================================================================
// ToolDefinition builder
// =============================================================================

#[test]
fn tool_definition_builder_defaults() {
    let td = ToolDefinition::new("test_tool");
    assert_eq!(td.name, "test_tool");
    assert!(td.description.is_empty());
    assert!(td.policy_gate);
    assert!(!td.human_gate);
    assert!(!td.human_gate_required);
    assert!(!td.scope_revalidated);
    assert!(td.cedar_resource.is_none());
    assert!(td.cedar_actions.is_empty());
}

#[test]
fn tool_definition_builder_chain() {
    let td = ToolDefinition::new("exploit_tool")
        .description("dangerous tool")
        .cedar_resource("PenTest::ScanTarget")
        .cedar_actions(&["PenTest::Action::scan"])
        .human_gate_required()
        .scope_revalidated();

    assert_eq!(td.description, "dangerous tool");
    assert_eq!(td.cedar_resource.unwrap(), "PenTest::ScanTarget");
    assert_eq!(td.cedar_actions, vec!["PenTest::Action::scan"]);
    assert!(td.human_gate_required);
    assert!(td.scope_revalidated);
    assert!(td.policy_gate);
}

#[test]
fn tool_definition_no_policy_gate() {
    let td = ToolDefinition::new("parser").no_policy_gate();
    assert!(!td.policy_gate);
}

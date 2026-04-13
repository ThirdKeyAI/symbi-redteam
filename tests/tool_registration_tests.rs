use symbi_redteam::{
    recon_tools, enum_tools, vuln_tools, exploit_tools,
    postexploit_tools, evidence_tools, reporting,
};

// =============================================================================
// Tool count verification — ensures no tools are accidentally dropped
// =============================================================================

#[test]
fn recon_tools_registers_7() {
    let tools = recon_tools::register_tools();
    assert_eq!(tools.len(), 7, "recon should register 7 tools");
}

#[test]
fn enum_tools_registers_5() {
    let tools = enum_tools::register_tools();
    assert_eq!(tools.len(), 5, "enum should register 5 tools");
}

#[test]
fn vuln_tools_registers_4() {
    let tools = vuln_tools::register_tools();
    assert_eq!(tools.len(), 4, "vuln should register 4 tools");
}

#[test]
fn exploit_tools_registers_4() {
    let tools = exploit_tools::register_tools();
    assert_eq!(tools.len(), 4, "exploit should register 4 tools");
}

#[test]
fn postexploit_tools_registers_4() {
    let tools = postexploit_tools::register_tools();
    assert_eq!(tools.len(), 4, "postexploit should register 4 tools");
}

#[test]
fn evidence_tools_registers_5() {
    let tools = evidence_tools::register_tools();
    assert_eq!(tools.len(), 5, "evidence should register 5 tools");
}

#[test]
fn reporting_tools_registers_4() {
    let tools = reporting::register_tools();
    assert_eq!(tools.len(), 4, "reporting should register 4 tools");
}

#[test]
fn total_tools_is_33() {
    let total = recon_tools::register_tools().len()
        + enum_tools::register_tools().len()
        + vuln_tools::register_tools().len()
        + exploit_tools::register_tools().len()
        + postexploit_tools::register_tools().len()
        + evidence_tools::register_tools().len()
        + reporting::register_tools().len();
    assert_eq!(total, 33, "total tools should be 33");
}

// =============================================================================
// Tool name uniqueness — no duplicate tool names across all modules
// =============================================================================

#[test]
fn all_tool_names_are_unique() {
    let mut names = Vec::new();
    for tool in recon_tools::register_tools() { names.push(tool.name); }
    for tool in enum_tools::register_tools() { names.push(tool.name); }
    for tool in vuln_tools::register_tools() { names.push(tool.name); }
    for tool in exploit_tools::register_tools() { names.push(tool.name); }
    for tool in postexploit_tools::register_tools() { names.push(tool.name); }
    for tool in evidence_tools::register_tools() { names.push(tool.name); }
    for tool in reporting::register_tools() { names.push(tool.name); }

    let count = names.len();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), count, "found duplicate tool names");
}

// =============================================================================
// Cedar resource verification — all gated tools must have Cedar resources
// =============================================================================

#[test]
fn all_gated_tools_have_cedar_resource() {
    let all_tools: Vec<_> = [
        recon_tools::register_tools(),
        enum_tools::register_tools(),
        vuln_tools::register_tools(),
        exploit_tools::register_tools(),
        postexploit_tools::register_tools(),
        evidence_tools::register_tools(),
        reporting::register_tools(),
    ].into_iter().flatten().collect();

    for tool in &all_tools {
        if tool.policy_gate {
            assert!(
                tool.cedar_resource.is_some(),
                "Tool '{}' has policy gate but no Cedar resource",
                tool.name,
            );
            assert!(
                !tool.cedar_actions.is_empty(),
                "Tool '{}' has policy gate but no Cedar actions",
                tool.name,
            );
        }
    }
}

// =============================================================================
// Human gate verification — exploit and post-exploit tools must be gated
// =============================================================================

#[test]
fn exploit_tools_require_human_gate() {
    for tool in exploit_tools::register_tools() {
        assert!(
            tool.human_gate_required,
            "Exploit tool '{}' must require human gate",
            tool.name,
        );
    }
}

#[test]
fn postexploit_tools_are_human_gated_and_scope_revalidated() {
    for tool in postexploit_tools::register_tools() {
        assert!(
            tool.human_gate,
            "Post-exploit tool '{}' must be human-gated",
            tool.name,
        );
        assert!(
            tool.scope_revalidated,
            "Post-exploit tool '{}' must require scope revalidation",
            tool.name,
        );
    }
}

// =============================================================================
// Specific tool name checks
// =============================================================================

#[test]
fn recon_tools_expected_names() {
    let names: Vec<String> = recon_tools::register_tools().iter().map(|t| t.name.clone()).collect();
    assert!(names.contains(&"nmap_scan".to_string()));
    assert!(names.contains(&"whois_lookup".to_string()));
    assert!(names.contains(&"dns_enumerate".to_string()));
    assert!(names.contains(&"whatweb_scan".to_string()));
    assert!(names.contains(&"amass_enum".to_string()));
    assert!(names.contains(&"parse_nmap_xml".to_string()));
    assert!(names.contains(&"lookup_cve".to_string()));
}

#[test]
fn parse_nmap_xml_has_no_policy_gate() {
    let tools = recon_tools::register_tools();
    let parser = tools.iter().find(|t| t.name == "parse_nmap_xml").unwrap();
    assert!(!parser.policy_gate, "parse_nmap_xml should have no policy gate");
}

#[test]
fn all_tools_have_descriptions() {
    let all_tools: Vec<_> = [
        recon_tools::register_tools(),
        enum_tools::register_tools(),
        vuln_tools::register_tools(),
        exploit_tools::register_tools(),
        postexploit_tools::register_tools(),
        evidence_tools::register_tools(),
        reporting::register_tools(),
    ].into_iter().flatten().collect();

    for tool in &all_tools {
        assert!(
            !tool.description.is_empty(),
            "Tool '{}' has an empty description",
            tool.name,
        );
    }
}

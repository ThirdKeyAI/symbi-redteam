// =============================================================================
// tool-authorization.cedar
//
// Per-tool risk tiering and authorization policies.
// Evaluated at the ORGA Gate phase -- outside LLM influence.
//
// Tools are categorized by risk level. Lower-risk tools are auto-allowed
// in their appropriate phase; higher-risk tools require additional controls
// such as rate limits, environment restrictions, or human approval.
//
// Risk tiers:
//   LOW         - Passive reconnaissance, auto-allowed
//   MEDIUM      - Active enumeration, allowed with rate limits
//   MEDIUM-HIGH - Vulnerability assessment, non-production only
//   HIGH        - Exploitation, requires human approval
//   HIGHEST     - Post-exploitation, requires approval + scope revalidation
//   EVIDENCE    - Evidence management, always allowed
//   REPORTING   - Report generation, allowed in reporting phase
// =============================================================================

// ---------------------------------------------------------------------------
// LOW RISK -- RECON PHASE TOOLS
//
// Passive reconnaissance tools that generate minimal network noise.
// Auto-allowed during recon phase on in-scope targets.
// ---------------------------------------------------------------------------

// nmap_scan -- network discovery and port scanning (recon-level)
permit (
    principal == PenTest::Phase::"recon",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "nmap_scan"
};

// whois_lookup -- domain/IP registration queries (passive, off-network)
permit (
    principal == PenTest::Phase::"recon",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "whois_lookup"
};

// dns_enumerate -- DNS record enumeration
permit (
    principal == PenTest::Phase::"recon",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "dns_enumerate"
};

// whatweb_scan -- web technology fingerprinting (passive)
permit (
    principal == PenTest::Phase::"recon",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "whatweb_scan"
};

// amass_enum -- subdomain enumeration and OSINT
permit (
    principal == PenTest::Phase::"recon",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "amass_enum"
};

// ---------------------------------------------------------------------------
// MEDIUM RISK -- ENUMERATION PHASE TOOLS
//
// Active enumeration tools that interact with target services.
// Allowed during enum phase with rate limits enforced by rate-limits.cedar.
// ---------------------------------------------------------------------------

// nikto_scan -- web server vulnerability scanner
permit (
    principal == PenTest::Phase::"enum",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "nikto_scan"
};

// gobuster_scan -- directory/file brute-forcing
permit (
    principal == PenTest::Phase::"enum",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "gobuster_scan"
};

// enum4linux_scan -- SMB/NetBIOS enumeration
permit (
    principal == PenTest::Phase::"enum",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "enum4linux_scan"
};

// smbclient_access -- SMB share enumeration and access
permit (
    principal == PenTest::Phase::"enum",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "smbclient_access"
};

// snmpwalk_enum -- SNMP tree enumeration
permit (
    principal == PenTest::Phase::"enum",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "snmpwalk_enum"
};

// ---------------------------------------------------------------------------
// MEDIUM-HIGH RISK -- VULNERABILITY ASSESSMENT TOOLS
//
// Active vulnerability scanning tools. Restricted to non-production
// environments only. These can cause service disruption if misconfigured.
// ---------------------------------------------------------------------------

// nmap_vuln_script -- NSE vulnerability scripts, non-production only
permit (
    principal == PenTest::Phase::"vuln",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "nmap_vuln_script" &&
    resource.environment == "non-production"
};

// nuclei_scan -- template-based vulnerability scanner, non-production only
permit (
    principal == PenTest::Phase::"vuln",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "nuclei_scan" &&
    resource.environment == "non-production"
};

// sqlmap_detect -- SQL injection detection (detection only), non-production only
permit (
    principal == PenTest::Phase::"vuln",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "sqlmap_detect" &&
    resource.environment == "non-production"
};

// searchsploit_query -- offline exploit database search (no network interaction)
// No environment restriction because this queries a local database only.
permit (
    principal == PenTest::Phase::"vuln",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "searchsploit_query"
};

// ---------------------------------------------------------------------------
// HIGH RISK -- EXPLOITATION TOOLS
//
// Active exploitation tools. These attempt to compromise target systems.
// Requires human approval with 30-minute expiry. Approval enforcement
// is defined in escalation.cedar; this policy gates the phase and tool.
// ---------------------------------------------------------------------------

// hydra_bruteforce -- credential brute-forcing
permit (
    principal == PenTest::Phase::"exploit",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "hydra_bruteforce" &&
    context.has_human_approval == true &&
    context.approval_age_minutes < 30
};

// metasploit_run -- exploit framework execution
permit (
    principal == PenTest::Phase::"exploit",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "metasploit_run" &&
    context.has_human_approval == true &&
    context.approval_age_minutes < 30
};

// sqlmap_exploit -- SQL injection exploitation
permit (
    principal == PenTest::Phase::"exploit",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "sqlmap_exploit" &&
    context.has_human_approval == true &&
    context.approval_age_minutes < 30
};

// sqlmap_dump -- database content extraction via SQL injection
permit (
    principal == PenTest::Phase::"exploit",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "sqlmap_dump" &&
    context.has_human_approval == true &&
    context.approval_age_minutes < 30
};

// Block exploit tools without approval -- explicit deny
forbid (
    principal == PenTest::Phase::"exploit",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name in ["hydra_bruteforce", "metasploit_run", "sqlmap_exploit", "sqlmap_dump"] &&
    context.has_human_approval != true
};

// ---------------------------------------------------------------------------
// HIGHEST RISK -- POST-EXPLOITATION TOOLS
//
// Post-exploitation tools for lateral movement, credential harvesting,
// and tunneling. Requires human approval AND scope revalidation to confirm
// the target is still in-scope after initial compromise.
// ---------------------------------------------------------------------------

// impacket_exec -- remote command execution via SMB/WMI/DCOM
permit (
    principal == PenTest::Phase::"post_exploit",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "impacket_exec" &&
    context.has_human_approval == true &&
    context.approval_age_minutes < 30 &&
    context.scope_revalidated == true
};

// pypykatz_dump -- credential extraction from memory/registry
permit (
    principal == PenTest::Phase::"post_exploit",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "pypykatz_dump" &&
    context.has_human_approval == true &&
    context.approval_age_minutes < 30 &&
    context.scope_revalidated == true
};

// chisel_tunnel -- TCP/UDP tunnel for pivoting
permit (
    principal == PenTest::Phase::"post_exploit",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "chisel_tunnel" &&
    context.has_human_approval == true &&
    context.approval_age_minutes < 30 &&
    context.scope_revalidated == true
};

// ligolo_proxy -- reverse tunnel proxy for pivoting
permit (
    principal == PenTest::Phase::"post_exploit",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "ligolo_proxy" &&
    context.has_human_approval == true &&
    context.approval_age_minutes < 30 &&
    context.scope_revalidated == true
};

// Block post-exploit tools without approval + scope revalidation
forbid (
    principal == PenTest::Phase::"post_exploit",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name in ["impacket_exec", "pypykatz_dump", "chisel_tunnel", "ligolo_proxy"] &&
    (context.has_human_approval != true || context.scope_revalidated != true)
};

// ---------------------------------------------------------------------------
// EVIDENCE MANAGEMENT TOOLS -- ALWAYS ALLOWED
//
// These tools manage findings, evidence, and engagement metadata.
// They do not interact with target systems and carry no risk.
// All agents in all phases may use these tools.
// ---------------------------------------------------------------------------

permit (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "store_finding"
};

permit (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "query_findings"
};

permit (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "search_similar_findings"
};

permit (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "store_tool_run"
};

permit (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "capture_evidence"
};

permit (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "create_engagement"
};

permit (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "manage_engagement"
};

// ---------------------------------------------------------------------------
// REPORTING TOOLS -- REPORTING PHASE
//
// Report generation and engagement comparison tools.
// Permitted during the reporting phase of the engagement.
// ---------------------------------------------------------------------------

// generate_report -- produce technical/executive pentest reports
permit (
    principal == PenTest::Phase::"reporting",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "generate_report"
};

// compare_engagements -- diff findings between engagements
permit (
    principal == PenTest::Phase::"reporting",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "compare_engagements"
};

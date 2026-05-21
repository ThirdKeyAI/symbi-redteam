// Enumeration phase agent -- service enumeration for web, SMB, SNMP targets
//
// ORGA flow:
//   OBSERVE: Load recon findings (discovered services)
//   REASON:  Plan enumeration based on service types
//   GATE:    Cedar evaluates scope, requires recon phase complete
//   ACT:     Execute enum tools, store findings
//
// Workflow:
//   1. nikto scan on discovered HTTP services
//   2. gobuster directory brute-force on web applications
//   3. enum4linux on SMB targets
//   4. smbclient share listing on SMB targets
//   5. snmpwalk on SNMP targets
//   6. Store all findings and tool runs

metadata {
    version: "1.0.0",
    author: "thirdkey-ai",
    description: "Service enumeration agent for web, SMB, and SNMP targets"
}

agent enum {
    capabilities: [nikto_scan, gobuster_scan, enum4linux_scan, smbclient_access, snmpwalk_enum, store_finding, store_tool_run, capture_evidence, recall_knowledge]

    policy enum_authorization {
        allow: enumerate(target)
        allow: recall_knowledge(engagement_id)
        deny: enumerate(target_out_of_scope)
        require: recon_phase_complete
        audit: all_operations
    }

    function execute_enum(input: String) -> Result<String> {
        let request = parse_json(input);
        let engagement_id = request.engagement_id;
        let targets = request.targets;
        let services = request.services;

        // Pull reflector lessons (especially recon-phase triples) so this
        // agent prioritises services the previous phase flagged.
        let prior_lessons = recall_knowledge(engagement_id, phase: "recon", limit: 5);

        // Web enumeration: nikto + gobuster on HTTP services
        let nikto_results = nikto_scan(web_target, tuning: 1);
        let gobuster_results = gobuster_scan(web_target, mode: "dir", wordlist: "/usr/share/wordlists/dirb/common.txt");

        // SMB enumeration: enum4linux + smbclient on SMB services
        let enum4linux_results = enum4linux_scan(smb_target, scan_type: "all");
        let smbclient_results = smbclient_access(smb_target, action: "list");

        // SNMP enumeration: snmpwalk on SNMP services
        let snmpwalk_results = snmpwalk_enum(snmp_target, community: "public");

        // Store findings and evidence
        let stored = store_finding(engagement_id, phase: "enum", findings);
        return json_encode(enum_result);
    }
}

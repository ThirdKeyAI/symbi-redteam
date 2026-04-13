// Reconnaissance phase agent -- network discovery, fingerprinting, CVE lookup
//
// ORGA flow:
//   OBSERVE: Parse targets from engagement controller
//   REASON:  Plan reconnaissance strategy
//   GATE:    Cedar evaluates scope and rate limits
//   ACT:     Execute recon tools, store findings
//
// Workflow:
//   1. nmap service scan on each target to discover hosts and open ports
//   2. whois lookup on discovered IPs
//   3. DNS enumeration on domain targets
//   4. whatweb fingerprinting on discovered HTTP services
//   5. amass subdomain enumeration (passive) on domain targets
//   6. CVE lookup for identified service versions
//   7. Store all findings and tool runs in evidence database

metadata {
    version: "1.0.0",
    author: "thirdkey-ai",
    description: "Network reconnaissance agent with multi-tool parallel execution"
}

agent recon {
    capabilities: [nmap_scan, whois_lookup, dns_enumerate, whatweb_scan, amass_enum, parse_nmap_xml, lookup_cve, store_finding, store_tool_run, capture_evidence]

    policy recon_authorization {
        allow: scan(target)
        deny: scan(target_out_of_scope)
        audit: all_operations
    }

    function execute_recon(input: String) -> Result<String> {
        // Parse the engagement request
        let request = parse_json(input);
        let engagement_id = request.engagement_id;
        let targets = request.targets;

        // Phase 1: Network discovery -- nmap service scan on each target
        // Use -sT (TCP connect) with service version detection
        // Store each scan result and parse XML output
        let nmap_results = nmap_scan(target, scan_type: "service");
        let parsed = parse_nmap_xml(nmap_results.output_file);

        // For each discovered service with a version, run CVE lookup
        let cve_results = lookup_cve(service, version);

        // Phase 2: Enrichment -- parallel whois, DNS, whatweb, amass
        let whois_results = whois_lookup(target);
        let dns_results = dns_enumerate(target, record_type: "ANY");
        let whatweb_results = whatweb_scan(web_target, aggression_level: 1);
        let amass_results = amass_enum(target, passive_only: true);

        // Store all findings and evidence
        let stored = store_finding(engagement_id, phase: "recon", findings);
        let evidence = capture_evidence(engagement_id, scan_outputs);

        return json_encode(recon_result);
    }
}

// =============================================================================
// scan-authorization.cedar
//
// Target and scan type authorization policies.
// Evaluated at the ORGA Gate phase -- outside LLM influence.
//
// These policies answer two questions:
//   1. Is the agent allowed to scan this target?
//   2. Is the requested scan type appropriate for this target?
//
// Cedar evaluation happens in <1ms. No performance excuse to skip it.
// =============================================================================

// ---- Namespace: NmapRecon ----

// ---------------------------------------------------------------------------
// ALLOWED TARGET RANGES
//
// Deny-by-default: if a CIDR is not explicitly listed here, scanning it
// is forbidden. The LLM cannot override this -- the Gate is not an LLM.
// ---------------------------------------------------------------------------

// Allow scanning internal staging subnets
permit (
    principal == NmapRecon::Agent::"nmap_recon",
    action == NmapRecon::Action::"scan",
    resource
)
when {
    resource.cidr like "10.0.1.*" ||   // Staging subnet A
    resource.cidr like "10.0.2.*" ||   // Staging subnet B
    resource.cidr like "192.168.10.*"  // Lab/test network
};

// Allow scanning the DMZ for production monitoring (limited scan types only)
permit (
    principal == NmapRecon::Agent::"nmap_recon",
    action == NmapRecon::Action::"scan",
    resource
)
when {
    resource.cidr like "10.10.0.*" &&
    resource.environment == "dmz" &&
    resource.scan_type in ["ping", "service"]      // Only ping and service detection
};

// ---------------------------------------------------------------------------
// DENIED TARGETS
//
// Explicit deny rules override permits. These are non-negotiable.
// ---------------------------------------------------------------------------

// Never scan production database subnets
forbid (
    principal,
    action == NmapRecon::Action::"scan",
    resource
)
when {
    resource.cidr like "10.100.*"       // Production DB subnet
};

// Never scan external/internet targets
forbid (
    principal,
    action == NmapRecon::Action::"scan",
    resource
)
when {
    resource.is_external == true
};

// Never scan RFC 1918 ranges we don't own
forbid (
    principal,
    action == NmapRecon::Action::"scan",
    resource
)
when {
    resource.cidr like "172.16.*" ||
    resource.cidr like "172.17.*" ||
    resource.cidr like "172.18.*"
};

// ---------------------------------------------------------------------------
// SCAN TYPE AUTHORIZATION
//
// Different scan types carry different risk levels. Policy gates them
// based on the target environment and the requester's role.
// ---------------------------------------------------------------------------

// Ping and service scans: always allowed on permitted targets
permit (
    principal == NmapRecon::Agent::"nmap_recon",
    action == NmapRecon::Action::"execute_scan_type",
    resource
)
when {
    resource.scan_type in ["ping", "service", "version"]
};

// SYN scans: allowed on non-production targets only
permit (
    principal == NmapRecon::Agent::"nmap_recon",
    action == NmapRecon::Action::"execute_scan_type",
    resource
)
when {
    resource.scan_type == "syn" &&
    resource.environment in ["staging", "development", "lab"]
};

// OS detection: requires the request to have "elevated" priority
permit (
    principal == NmapRecon::Agent::"nmap_recon",
    action == NmapRecon::Action::"execute_scan_type",
    resource
)
when {
    resource.scan_type == "os_detect" &&
    resource.priority in ["urgent", "incident_response"]
};

// Aggressive scans and vulnerability scripts: always denied by agent alone.
// These require human approval (handled by escalation.cedar).
forbid (
    principal == NmapRecon::Agent::"nmap_recon",
    action == NmapRecon::Action::"execute_scan_type",
    resource
)
when {
    resource.scan_type in ["aggressive", "vuln_script"]
};

// Exploit and brute force: unconditionally forbidden. No escalation path.
forbid (
    principal,
    action == NmapRecon::Action::"execute_scan_type",
    resource
)
when {
    resource.scan_type in ["exploit", "brute_force"]
};

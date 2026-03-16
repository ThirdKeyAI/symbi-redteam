// =============================================================================
// scope.cedar
//
// Target scope enforcement policies for penetration testing engagements.
// Evaluated at the ORGA Gate phase -- outside LLM influence.
//
// These policies define which network targets are in-scope and which are
// unconditionally forbidden. Deny-by-default: if a CIDR is not explicitly
// permitted here, all actions against it are blocked. The LLM cannot
// override these boundaries -- the Gate is not an LLM.
//
// Target categories:
//   - Allowed (non-production): staging, dev, lab -- all phases permitted
//   - DMZ: limited to recon phase, restricted scan types
//   - Excluded: core infrastructure, finance VLAN, production DB
//   - External: unconditionally blocked
//   - Unowned RFC 1918: unconditionally blocked
// =============================================================================

// ---------------------------------------------------------------------------
// ALLOWED TARGET RANGES (non-production)
//
// These subnets are fully in-scope for all engagement phases.
// All tool categories are permitted subject to phase-gate and tool-auth
// policies defined elsewhere.
// ---------------------------------------------------------------------------

// Staging subnet -- full scope
permit (
    principal,
    action == PenTest::Action::"scan",
    resource
)
when {
    resource.cidr like "10.0.1.*" &&
    resource.environment == "non-production"
};

permit (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.cidr like "10.0.1.*" &&
    resource.environment == "non-production"
};

// Development subnet -- full scope
permit (
    principal,
    action == PenTest::Action::"scan",
    resource
)
when {
    resource.cidr like "10.0.2.*" &&
    resource.environment == "non-production"
};

permit (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.cidr like "10.0.2.*" &&
    resource.environment == "non-production"
};

// Lab/test network -- full scope
permit (
    principal,
    action == PenTest::Action::"scan",
    resource
)
when {
    resource.cidr like "192.168.10.*" &&
    resource.environment == "non-production"
};

permit (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.cidr like "192.168.10.*" &&
    resource.environment == "non-production"
};

// ---------------------------------------------------------------------------
// DMZ -- LIMITED SCOPE
//
// The DMZ is in-scope for recon phase only. Only passive/low-impact scan
// types are permitted: ping, service detection, and version detection.
// No enumeration, exploitation, or post-exploitation against DMZ targets.
// ---------------------------------------------------------------------------

// DMZ: recon-phase scanning with restricted scan types
permit (
    principal == PenTest::Phase::"recon",
    action == PenTest::Action::"scan",
    resource
)
when {
    resource.cidr like "10.10.0.*" &&
    resource.scan_type in ["ping", "service", "version"]
};

permit (
    principal == PenTest::Phase::"recon",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.cidr like "10.10.0.*" &&
    resource.scan_type in ["ping", "service", "version"]
};

// Block DMZ for all non-recon phases explicitly
forbid (
    principal == PenTest::Phase::"enum",
    action,
    resource
)
when {
    resource.cidr like "10.10.0.*"
};

forbid (
    principal == PenTest::Phase::"vuln",
    action,
    resource
)
when {
    resource.cidr like "10.10.0.*"
};

forbid (
    principal == PenTest::Phase::"exploit",
    action,
    resource
)
when {
    resource.cidr like "10.10.0.*"
};

forbid (
    principal == PenTest::Phase::"post_exploit",
    action,
    resource
)
when {
    resource.cidr like "10.10.0.*"
};

// ---------------------------------------------------------------------------
// EXCLUDED TARGETS -- UNCONDITIONAL DENY
//
// These forbid rules override any permit. They protect critical
// infrastructure that must never be touched during penetration testing.
// ---------------------------------------------------------------------------

// Core router -- critical network infrastructure
forbid (
    principal,
    action,
    resource
)
when {
    resource.cidr == "10.0.0.1"
};

// Primary DNS server -- critical network infrastructure
forbid (
    principal,
    action,
    resource
)
when {
    resource.cidr == "10.0.0.2"
};

// Finance VLAN -- out of scope, regulatory restrictions
forbid (
    principal,
    action,
    resource
)
when {
    resource.cidr like "10.0.100.*"
};

// ---------------------------------------------------------------------------
// EXTERNAL TARGETS -- UNCONDITIONAL DENY
//
// The engagement scope is internal-only. Any target flagged as external
// by the runtime is unconditionally blocked regardless of CIDR.
// ---------------------------------------------------------------------------

forbid (
    principal,
    action,
    resource
)
when {
    resource.is_external == true
};

// ---------------------------------------------------------------------------
// UNOWNED RFC 1918 RANGES -- UNCONDITIONAL DENY
//
// These private ranges belong to other departments or tenants.
// Scanning them would be out-of-scope and potentially illegal.
// ---------------------------------------------------------------------------

forbid (
    principal,
    action,
    resource
)
when {
    resource.cidr like "172.16.*"
};

forbid (
    principal,
    action,
    resource
)
when {
    resource.cidr like "172.17.*"
};

forbid (
    principal,
    action,
    resource
)
when {
    resource.cidr like "172.18.*"
};

// ---------------------------------------------------------------------------
// PRODUCTION DATABASE SUBNET -- UNCONDITIONAL DENY
//
// Production databases are never in-scope for penetration testing.
// ---------------------------------------------------------------------------

forbid (
    principal,
    action,
    resource
)
when {
    resource.cidr like "10.100.*"
};

// =============================================================================
// rate-limits.cedar
//
// Scan frequency governance. Prevents:
//   - Accidental scan storms (LLM loops requesting repeated scans)
//   - Intentional abuse via prompt injection
//   - Resource exhaustion on target networks
//
// Rate counters are maintained by the Symbiont runtime and passed
// to Cedar as context attributes. The LLM has no access to these
// counters and cannot reset or manipulate them.
// =============================================================================

// ---------------------------------------------------------------------------
// PER-TARGET RATE LIMITS
// ---------------------------------------------------------------------------

// Max 10 scans per hour against any single CIDR
forbid (
    principal,
    action == NmapRecon::Action::"scan",
    resource
)
when {
    context.rate_counters.target_scans_1h > 10
};

// Max 3 SYN scans per hour against any single CIDR
// (SYN scans are noisier and more likely to trigger IDS)
forbid (
    principal,
    action == NmapRecon::Action::"execute_scan_type",
    resource
)
when {
    resource.scan_type == "syn" &&
    context.rate_counters.target_syn_scans_1h > 3
};

// ---------------------------------------------------------------------------
// GLOBAL RATE LIMITS
// ---------------------------------------------------------------------------

// Max 100 total scans per hour across all targets
forbid (
    principal,
    action == NmapRecon::Action::"scan",
    resource
)
when {
    context.rate_counters.global_scans_1h > 100
};

// Max 1000 total scans per day
forbid (
    principal,
    action == NmapRecon::Action::"scan",
    resource
)
when {
    context.rate_counters.global_scans_24h > 1000
};

// ---------------------------------------------------------------------------
// CONCURRENT SCAN LIMITS
// ---------------------------------------------------------------------------

// Max 3 concurrent scans running at the same time
forbid (
    principal,
    action == NmapRecon::Action::"scan",
    resource
)
when {
    context.active_scans > 3
};

// ---------------------------------------------------------------------------
// INCIDENT RESPONSE OVERRIDE
//
// During active incident response, rate limits are relaxed (not removed).
// This still requires the target to be in allowed CIDRs -- scan-authorization
// policies are not overridden.
// ---------------------------------------------------------------------------

permit (
    principal == NmapRecon::Agent::"nmap_recon",
    action == NmapRecon::Action::"scan",
    resource
)
when {
    context.mode == "incident_response" &&
    context.rate_counters.global_scans_1h <= 500   // 5x normal limit
};

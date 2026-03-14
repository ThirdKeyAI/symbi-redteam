// =============================================================================
// escalation.cedar
//
// Defines when the ORGA Gate must pause for human approval.
// Symbiont's human_critic module handles the approval workflow:
//   1. Gate evaluates action and finds "require_approval" decision
//   2. Runtime sends approval request to configured channel (Slack/Teams/email)
//   3. Agent suspends until approval or timeout
//   4. On approval: Gate re-evaluates with approval context, action proceeds
//   5. On denial/timeout: action is blocked and logged
//
// This is the "human-in-the-loop" that enterprises require for high-risk
// autonomous operations. The agent cannot skip this step.
// =============================================================================

// ---------------------------------------------------------------------------
// SCANS REQUIRING HUMAN APPROVAL
// ---------------------------------------------------------------------------

// OS fingerprinting on any target requires approval
// (noisy, can trigger IDS, reveals scanning intent)
permit (
    principal == NmapRecon::Agent::"nmap_recon",
    action == NmapRecon::Action::"execute_scan_type",
    resource
)
when {
    resource.scan_type == "os_detect" &&
    context.has_human_approval == true &&
    context.approval_age_minutes < 60           // Approval expires after 1 hour
};

// Aggressive scans require approval and are limited to incident response
permit (
    principal == NmapRecon::Agent::"nmap_recon",
    action == NmapRecon::Action::"execute_scan_type",
    resource
)
when {
    resource.scan_type == "aggressive" &&
    context.has_human_approval == true &&
    context.approval_age_minutes < 30 &&        // Tighter expiry for aggressive
    context.mode == "incident_response"         // Only during active incidents
};

// Vulnerability script scans: approval + incident response + non-production only
permit (
    principal == NmapRecon::Agent::"nmap_recon",
    action == NmapRecon::Action::"execute_scan_type",
    resource
)
when {
    resource.scan_type == "vuln_script" &&
    context.has_human_approval == true &&
    context.approval_age_minutes < 30 &&
    context.mode == "incident_response" &&
    resource.environment != "production"
};

// ---------------------------------------------------------------------------
// APPROVAL AUDIT
//
// All approval decisions (granted and denied) are logged to the
// cryptographic audit trail. This creates a tamper-evident record of
// who approved what, when, and from which channel.
// ---------------------------------------------------------------------------

// (Audit logging is handled by the runtime, not by Cedar policy.
//  The policies above gate the actions; the runtime logs everything.)

// ---------------------------------------------------------------------------
// SCANNING NEW/UNKNOWN TARGETS
//
// If a target CIDR hasn't been scanned before (no history in the vector
// store), require human approval for the first scan. This prevents the
// LLM from "discovering" new targets through creative reasoning.
// ---------------------------------------------------------------------------

permit (
    principal == NmapRecon::Agent::"nmap_recon",
    action == NmapRecon::Action::"scan",
    resource
)
when {
    resource.is_first_scan == true &&
    context.has_human_approval == true
};

// Block first-scan without approval (this forbid fires before the
// general permit in scan-authorization.cedar)
forbid (
    principal == NmapRecon::Agent::"nmap_recon",
    action == NmapRecon::Action::"scan",
    resource
)
when {
    resource.is_first_scan == true &&
    context.has_human_approval != true
};

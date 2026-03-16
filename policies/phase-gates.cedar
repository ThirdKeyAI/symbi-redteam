// =============================================================================
// phase-gates.cedar
//
// Penetration testing methodology enforcement.
// Evaluated at the ORGA Gate phase -- outside LLM influence.
//
// Ensures the engagement follows a structured methodology where each phase
// must satisfy prerequisites before advancing. This prevents the LLM from
// skipping reconnaissance and jumping straight to exploitation, which would
// be both ineffective and potentially dangerous.
//
// Phase progression:
//   recon -> enum -> vuln -> exploit -> post_exploit -> reporting
//
// Each phase gate checks context attributes maintained by the Symbiont
// runtime. The LLM cannot manipulate these counters or flags.
// =============================================================================

// ---------------------------------------------------------------------------
// RECON PHASE -- ALWAYS ALLOWED
//
// Reconnaissance is the entry point for any engagement. It requires only
// that the engagement is active (not expired, not revoked).
// ---------------------------------------------------------------------------

permit (
    principal == PenTest::Phase::"recon",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    context.engagement_status == "active"
};

permit (
    principal == PenTest::Phase::"recon",
    action == PenTest::Action::"scan",
    resource
)
when {
    context.engagement_status == "active"
};

// ---------------------------------------------------------------------------
// ENUM PHASE -- REQUIRES RECON FINDINGS
//
// Enumeration may begin only after reconnaissance has produced at least
// one finding. This ensures the agent has actually performed recon rather
// than attempting to skip ahead.
// ---------------------------------------------------------------------------

permit (
    principal == PenTest::Phase::"enum",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    context.engagement_status == "active" &&
    context.recon_findings_count >= 1
};

permit (
    principal == PenTest::Phase::"enum",
    action == PenTest::Action::"scan",
    resource
)
when {
    context.engagement_status == "active" &&
    context.recon_findings_count >= 1
};

// Block enum phase when no recon findings exist
forbid (
    principal == PenTest::Phase::"enum",
    action,
    resource
)
when {
    context.recon_findings_count < 1
};

// ---------------------------------------------------------------------------
// VULN PHASE -- REQUIRES ENUMERATION COMPLETE
//
// Vulnerability assessment may begin only after enumeration has been
// marked complete by the runtime. This ensures thorough enumeration
// before attempting to identify vulnerabilities.
// ---------------------------------------------------------------------------

permit (
    principal == PenTest::Phase::"vuln",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    context.engagement_status == "active" &&
    context.enum_complete == true
};

permit (
    principal == PenTest::Phase::"vuln",
    action == PenTest::Action::"scan",
    resource
)
when {
    context.engagement_status == "active" &&
    context.enum_complete == true
};

// Block vuln phase when enumeration is not complete
forbid (
    principal == PenTest::Phase::"vuln",
    action,
    resource
)
when {
    context.enum_complete != true
};

// ---------------------------------------------------------------------------
// EXPLOIT PHASE -- REQUIRES VULN ASSESSMENT AND REVIEW
//
// Exploitation may begin only after:
//   1. Vulnerability assessment is marked complete
//   2. Vulnerability findings have been reviewed (human or automated QA)
//
// This two-gate check prevents blind exploitation and ensures findings
// are validated before attempting active exploitation.
// ---------------------------------------------------------------------------

permit (
    principal == PenTest::Phase::"exploit",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    context.engagement_status == "active" &&
    context.vuln_assessment_complete == true &&
    context.vuln_findings_reviewed == true
};

permit (
    principal == PenTest::Phase::"exploit",
    action == PenTest::Action::"scan",
    resource
)
when {
    context.engagement_status == "active" &&
    context.vuln_assessment_complete == true &&
    context.vuln_findings_reviewed == true
};

// Block exploit phase when prerequisites not met
forbid (
    principal == PenTest::Phase::"exploit",
    action,
    resource
)
when {
    context.vuln_assessment_complete != true ||
    context.vuln_findings_reviewed != true
};

// ---------------------------------------------------------------------------
// POST-EXPLOIT PHASE -- REQUIRES SUCCESSFUL EXPLOITATION
//
// Post-exploitation activities (lateral movement, credential harvesting,
// persistence testing) may begin only after at least one exploit has
// succeeded. This prevents post-exploitation tools from being used
// before a foothold is established.
// ---------------------------------------------------------------------------

permit (
    principal == PenTest::Phase::"post_exploit",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    context.engagement_status == "active" &&
    context.exploit_success_count >= 1
};

permit (
    principal == PenTest::Phase::"post_exploit",
    action == PenTest::Action::"scan",
    resource
)
when {
    context.engagement_status == "active" &&
    context.exploit_success_count >= 1
};

// Block post-exploit phase when no successful exploits exist
forbid (
    principal == PenTest::Phase::"post_exploit",
    action,
    resource
)
when {
    context.exploit_success_count < 1
};

// ---------------------------------------------------------------------------
// REPORTING PHASE -- ALLOWED WHEN ACTIVE OR COMPLETE
//
// Report generation is allowed both during an active engagement (interim
// reports) and after engagement completion (final reports). This is the
// only phase permitted after engagement completion.
// ---------------------------------------------------------------------------

permit (
    principal == PenTest::Phase::"reporting",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    context.engagement_status == "active" ||
    context.engagement_status == "complete"
};

permit (
    principal == PenTest::Phase::"reporting",
    action == PenTest::Action::"scan",
    resource
)
when {
    context.engagement_status == "active" ||
    context.engagement_status == "complete"
};

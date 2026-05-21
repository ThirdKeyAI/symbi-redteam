// =============================================================================
// validation.cedar
//
// Structural separation of duties between finding *creation* and finding
// *verification*. Evaluated at the ORGA Gate -- outside LLM influence.
//
// The validate agent (principal == PenTest::Phase::"validate") is the sole
// principal authorised to flip the `verified` / `false_positive` flags on
// findings via verify_finding / mark_false_positive. Conversely, validate
// is structurally forbidden from calling store_finding, so it cannot
// fabricate the very findings it is supposed to adjudicate.
//
// This complements evidence.cedar, which already blocks report generation
// while unverified_critical_high_count > 0. Without validation.cedar there
// is no agent allowed to satisfy that gate, so the report path deadlocks.
// =============================================================================

// ---------------------------------------------------------------------------
// VALIDATE PERMISSIONS
//
// Permit the validate agent to verify or reject findings during an active
// engagement. Other read tools (query_findings, search_similar_findings)
// are governed by their existing tool-authorization rules.
// ---------------------------------------------------------------------------

permit (
    principal == PenTest::Phase::"validate",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    context.engagement_status == "active" &&
    (resource.tool_name == "verify_finding" ||
     resource.tool_name == "mark_false_positive" ||
     resource.tool_name == "query_findings" ||
     resource.tool_name == "search_similar_findings" ||
     resource.tool_name == "store_tool_run" ||
     resource.tool_name == "capture_evidence")
};

// ---------------------------------------------------------------------------
// STRUCTURAL DENIAL -- VALIDATE MAY NOT CREATE FINDINGS
//
// Even if a future capability list or tool-authorization rule were to grant
// the validate agent store_finding, this forbid wins under Cedar's
// deny-overrides semantics. Validation cannot manufacture the evidence
// it adjudicates.
// ---------------------------------------------------------------------------

forbid (
    principal == PenTest::Phase::"validate",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "store_finding"
};

// ---------------------------------------------------------------------------
// STRUCTURAL DENIAL -- ONLY VALIDATE MAY VERIFY FINDINGS
//
// Phase agents that produce findings (recon, enum, vuln, exploit,
// post_exploit) and the reporter must never mark their own work verified.
// Every non-validate principal is forbidden from calling verify_finding
// or mark_false_positive.
// ---------------------------------------------------------------------------

forbid (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    (resource.tool_name == "verify_finding" ||
     resource.tool_name == "mark_false_positive") &&
    principal != PenTest::Phase::"validate"
};

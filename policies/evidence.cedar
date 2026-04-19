// =============================================================================
// evidence.cedar
//
// Evidence handling and data integrity policies.
// Evaluated at the ORGA Gate phase -- outside LLM influence.
//
// These policies enforce evidence management hygiene:
//   1. Tool runs must be stored before new tools can execute, ensuring
//      a complete audit trail with no gaps.
//   2. Reports cannot be generated while critical/high findings remain
//      unverified, preventing incomplete or inaccurate deliverables.
//
// The runtime tracks pending_tool_runs and unverified finding counts.
// The LLM cannot manipulate these counters.
// =============================================================================

// ---------------------------------------------------------------------------
// TOOL EXECUTION -- BLOCK WHEN EVIDENCE BACKLOG EXISTS
//
// If there are tool runs that have not yet been stored to the evidence
// store (pending_tool_runs > 0), block further tool execution. This
// ensures every tool run is captured before the agent moves on,
// maintaining an unbroken evidence chain.
//
// Evidence tools themselves are exempt from this check to avoid a
// deadlock where the agent cannot store evidence because evidence
// storage is blocked.
// ---------------------------------------------------------------------------

forbid (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    context.pending_tool_runs > 0 &&
    resource.tool_name != "store_tool_run" &&
    resource.tool_name != "store_finding" &&
    resource.tool_name != "capture_evidence" &&
    resource.tool_name != "query_findings" &&
    resource.tool_name != "search_similar_findings" &&
    resource.tool_name != "create_engagement" &&
    resource.tool_name != "manage_engagement" &&
    resource.tool_name != "store_knowledge" &&
    resource.tool_name != "recall_knowledge"
};

forbid (
    principal,
    action == PenTest::Action::"scan",
    resource
)
when {
    context.pending_tool_runs > 0
};

// ---------------------------------------------------------------------------
// REPORT GENERATION -- BLOCK WHEN UNVERIFIED CRITICAL/HIGH FINDINGS
//
// Technical reports must not be generated while critical or high severity
// findings remain unverified. This prevents delivery of reports containing
// unvalidated findings, which would undermine report credibility and could
// cause unnecessary alarm or missed vulnerabilities.
//
// The runtime tracks unverified_critical_high_count as the number of
// findings with severity "critical" or "high" that have not been
// verified by a human reviewer or automated validation.
// ---------------------------------------------------------------------------

forbid (
    principal == PenTest::Phase::"reporting",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "generate_report" &&
    context.unverified_critical_high_count > 0
};

// =============================================================================
// time-bounds.cedar
//
// Engagement window enforcement policies.
// Evaluated at the ORGA Gate phase -- outside LLM influence.
//
// Every penetration testing engagement has a defined time window with
// a start_time and end_time. These policies enforce strict temporal
// boundaries:
//
//   1. No actions before engagement start_time
//   2. Only reporting actions after engagement end_time
//   3. No actions at all (including reporting) after 24 hours past end_time
//
// Time values are provided by the Symbiont runtime as epoch timestamps.
// The LLM cannot manipulate the current time or engagement boundaries.
// =============================================================================

// ---------------------------------------------------------------------------
// PRE-ENGAGEMENT -- FORBID ALL ACTIONS
//
// Before the engagement start_time, no actions of any kind are permitted.
// This prevents early starts that would violate the rules of engagement
// and contractual obligations.
// ---------------------------------------------------------------------------

forbid (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    context.current_time < context.engagement_start_time
};

forbid (
    principal,
    action == PenTest::Action::"scan",
    resource
)
when {
    context.current_time < context.engagement_start_time
};

// ---------------------------------------------------------------------------
// POST-ENGAGEMENT -- REPORTING ONLY
//
// After the engagement end_time, only reporting-phase actions are allowed.
// All scanning, enumeration, exploitation, and post-exploitation are
// forbidden. This allows the team to finalize reports without risking
// unauthorized testing outside the engagement window.
// ---------------------------------------------------------------------------

// Block non-reporting actions after engagement end_time
forbid (
    principal == PenTest::Phase::"recon",
    action,
    resource
)
when {
    context.current_time > context.engagement_end_time
};

forbid (
    principal == PenTest::Phase::"enum",
    action,
    resource
)
when {
    context.current_time > context.engagement_end_time
};

forbid (
    principal == PenTest::Phase::"vuln",
    action,
    resource
)
when {
    context.current_time > context.engagement_end_time
};

forbid (
    principal == PenTest::Phase::"exploit",
    action,
    resource
)
when {
    context.current_time > context.engagement_end_time
};

forbid (
    principal == PenTest::Phase::"post_exploit",
    action,
    resource
)
when {
    context.current_time > context.engagement_end_time
};

// ---------------------------------------------------------------------------
// REPORTING DEADLINE -- 24 HOURS AFTER ENGAGEMENT END
//
// Reporting is allowed for up to 24 hours after the engagement end_time.
// After that, all actions are forbidden including report generation.
// This creates a hard deadline for deliverables and ensures engagement
// resources are released in a timely manner.
//
// The runtime calculates engagement_end_time_plus_24h as:
//   engagement_end_time + 86400 (seconds in 24 hours)
// ---------------------------------------------------------------------------

forbid (
    principal == PenTest::Phase::"reporting",
    action,
    resource
)
when {
    context.current_time > context.engagement_end_time_plus_24h
};

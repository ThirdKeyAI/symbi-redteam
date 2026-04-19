// =============================================================================
// reflector.cedar
//
// Bounds on the post-phase reflector agent. The reflector's only job is to
// distil lessons from a completed phase into subject-predicate-object
// triples and write them via store_knowledge. Every scan, enum, exploit,
// and post-exploit tool is off-limits.
//
// The structure follows symbiont-karpathy-loop's reflector policy: a
// narrowly-scoped permit plus a defensive forbid. The `unless` form on
// the forbid reads as "forbid execute_tool unless the tool is in this
// short whitelist", which catches future accidental widening. Even if a
// later edit adds store_knowledge to another phase's permit, this agent's
// surface stays bounded by the global forbid below.
// =============================================================================

// ---------------------------------------------------------------------------
// PERMIT -- the only two tools the reflector may call to do its job
// ---------------------------------------------------------------------------

permit (
    principal == PenTest::Phase::"reflector",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "store_knowledge" ||
    resource.tool_name == "recall_knowledge" ||
    resource.tool_name == "query_findings"
};

// ---------------------------------------------------------------------------
// GLOBAL FORBID -- catches any future tool the reflector must not call
//
// Reads as: "forbid execute_tool unless the tool is one of the three the
// reflector is explicitly allowed to use." If someone later adds a new
// recall-only helper tool, this clause forces them to update the list
// deliberately instead of silently widening the reflector's surface.
// ---------------------------------------------------------------------------

forbid (
    principal == PenTest::Phase::"reflector",
    action == PenTest::Action::"execute_tool",
    resource
)
unless {
    resource.tool_name == "store_knowledge" ||
    resource.tool_name == "recall_knowledge" ||
    resource.tool_name == "query_findings"
};

// The reflector must not scan, exploit, or otherwise touch targets.
// These are already covered by the forbid above (no permit matches
// these actions for this principal), but we declare them explicitly so
// a reader of this file can see the boundary at a glance.
forbid (
    principal == PenTest::Phase::"reflector",
    action == PenTest::Action::"scan",
    resource
);

forbid (
    principal == PenTest::Phase::"reflector",
    action == PenTest::Action::"exploit",
    resource
);

forbid (
    principal == PenTest::Phase::"reflector",
    action == PenTest::Action::"post_exploit",
    resource
);

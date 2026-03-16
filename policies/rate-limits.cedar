// =============================================================================
// rate-limits.cedar
//
// Tool execution frequency governance. Prevents:
//   - Accidental tool storms (LLM loops requesting repeated executions)
//   - Intentional abuse via prompt injection
//   - Resource exhaustion on target networks
//   - Detection by target IDS/IPS from excessive traffic
//
// Rate counters are maintained by the Symbiont runtime and passed
// to Cedar as context attributes. The LLM has no access to these
// counters and cannot reset or manipulate them.
//
// Limits are tiered by tool category to reflect operational risk:
//   - Recon tools: higher limits (lower impact)
//   - Enum tools: moderate limits
//   - Exploit tools: strict limits (highest impact)
// =============================================================================

// ---------------------------------------------------------------------------
// PER-TARGET RATE LIMITS BY CATEGORY
//
// These limits apply per-target (per CIDR) to prevent overwhelming
// any single target with too many tool executions.
// ---------------------------------------------------------------------------

// Recon tools: max 20 executions per hour per target
forbid (
    principal == PenTest::Phase::"recon",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    context.rate_counters.target_recon_runs_1h > 20
};

forbid (
    principal == PenTest::Phase::"recon",
    action == PenTest::Action::"scan",
    resource
)
when {
    context.rate_counters.target_recon_runs_1h > 20
};

// Enum tools: max 10 executions per hour per target
forbid (
    principal == PenTest::Phase::"enum",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    context.rate_counters.target_enum_runs_1h > 10
};

forbid (
    principal == PenTest::Phase::"enum",
    action == PenTest::Action::"scan",
    resource
)
when {
    context.rate_counters.target_enum_runs_1h > 10
};

// Exploit tools: max 3 executions per hour per target
// Strict limit -- exploitation is high-impact and noisy
forbid (
    principal == PenTest::Phase::"exploit",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    context.rate_counters.target_exploit_runs_1h > 3
};

// ---------------------------------------------------------------------------
// GLOBAL RATE LIMITS
//
// Aggregate limits across all targets to prevent runaway execution
// regardless of how many targets are in scope.
// ---------------------------------------------------------------------------

// Max 500 total tool runs per day across all targets and phases
forbid (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    context.rate_counters.global_runs_24h > 500
};

forbid (
    principal,
    action == PenTest::Action::"scan",
    resource
)
when {
    context.rate_counters.global_runs_24h > 500
};

// ---------------------------------------------------------------------------
// CONCURRENT EXECUTION LIMITS
//
// Prevents too many tools from running simultaneously, which could
// cause network saturation and increase detection risk.
// ---------------------------------------------------------------------------

// Recon: max 5 concurrent tool executions
forbid (
    principal == PenTest::Phase::"recon",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    context.active_tool_runs.recon > 5
};

forbid (
    principal == PenTest::Phase::"recon",
    action == PenTest::Action::"scan",
    resource
)
when {
    context.active_tool_runs.recon > 5
};

// Enum: max 3 concurrent tool executions
forbid (
    principal == PenTest::Phase::"enum",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    context.active_tool_runs.enum > 3
};

forbid (
    principal == PenTest::Phase::"enum",
    action == PenTest::Action::"scan",
    resource
)
when {
    context.active_tool_runs.enum > 3
};

// Exploit: max 1 concurrent tool execution
// Only one exploit at a time to maintain control and observability
forbid (
    principal == PenTest::Phase::"exploit",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    context.active_tool_runs.exploit > 1
};

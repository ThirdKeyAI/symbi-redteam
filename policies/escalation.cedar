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
//
// Approval tiers:
//   - OS fingerprint: 60min expiry (noisy but not destructive)
//   - Aggressive scan: 30min expiry (can cause service disruption)
//   - Exploit tools: 30min expiry, per-target (active exploitation)
//   - Post-exploit tools: 30min expiry, per-target + scope revalidation
//   - First-time target: approval required (prevents target discovery drift)
//
// All approval decisions (granted and denied) are logged to the
// cryptographic audit trail by the runtime.
// =============================================================================

// ---------------------------------------------------------------------------
// OS FINGERPRINTING -- APPROVAL WITH 60-MINUTE EXPIRY
//
// OS detection is noisy and can trigger IDS alerts. Requires approval
// but has a longer expiry window since it is not destructive.
// ---------------------------------------------------------------------------

permit (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.scan_type == "os_detect" &&
    context.has_human_approval == true &&
    context.approval_age_minutes < 60
};

// Block OS fingerprinting without approval
forbid (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.scan_type == "os_detect" &&
    context.has_human_approval != true
};

// ---------------------------------------------------------------------------
// AGGRESSIVE SCANNING -- APPROVAL WITH 30-MINUTE EXPIRY
//
// Aggressive scans (-T5, comprehensive NSE scripts) can cause service
// disruption and generate significant network noise. Tighter expiry.
// ---------------------------------------------------------------------------

permit (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.scan_type == "aggressive" &&
    context.has_human_approval == true &&
    context.approval_age_minutes < 30
};

// Block aggressive scanning without approval
forbid (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.scan_type == "aggressive" &&
    context.has_human_approval != true
};

// ---------------------------------------------------------------------------
// EXPLOIT TOOLS -- PER-TARGET APPROVAL WITH 30-MINUTE EXPIRY
//
// Exploitation tools actively attempt to compromise systems. Approval
// is scoped per-target -- approving exploitation of one target does not
// authorize exploitation of others.
// ---------------------------------------------------------------------------

permit (
    principal == PenTest::Phase::"exploit",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name in ["hydra_bruteforce", "metasploit_run", "sqlmap_exploit", "sqlmap_dump"] &&
    context.has_human_approval == true &&
    context.approval_age_minutes < 30 &&
    context.approval_target == resource.cidr
};

// Block exploit tools without per-target approval
forbid (
    principal == PenTest::Phase::"exploit",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name in ["hydra_bruteforce", "metasploit_run", "sqlmap_exploit", "sqlmap_dump"] &&
    (context.has_human_approval != true || context.approval_target != resource.cidr)
};

// ---------------------------------------------------------------------------
// POST-EXPLOIT TOOLS -- APPROVAL + SCOPE REVALIDATION, 30-MINUTE EXPIRY
//
// Post-exploitation is the highest-risk category. Beyond human approval,
// scope revalidation confirms that the target is still within the
// authorized engagement scope after initial compromise. This catches
// cases where lateral movement would reach out-of-scope systems.
// ---------------------------------------------------------------------------

permit (
    principal == PenTest::Phase::"post_exploit",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name in ["impacket_exec", "pypykatz_dump", "chisel_tunnel", "ligolo_proxy"] &&
    context.has_human_approval == true &&
    context.approval_age_minutes < 30 &&
    context.approval_target == resource.cidr &&
    context.scope_revalidated == true
};

// Block post-exploit tools without approval + scope revalidation
forbid (
    principal == PenTest::Phase::"post_exploit",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name in ["impacket_exec", "pypykatz_dump", "chisel_tunnel", "ligolo_proxy"] &&
    (context.has_human_approval != true || context.scope_revalidated != true || context.approval_target != resource.cidr)
};

// ---------------------------------------------------------------------------
// FIRST-TIME TARGET -- APPROVAL REQUIRED
//
// If a target CIDR has not been scanned before in this engagement,
// require human approval for the first interaction. This prevents the
// LLM from "discovering" new targets through creative reasoning or
// prompt injection and expanding scope without authorization.
// ---------------------------------------------------------------------------

permit (
    principal,
    action == PenTest::Action::"scan",
    resource
)
when {
    resource.is_first_scan == true &&
    context.has_human_approval == true
};

permit (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.is_first_scan == true &&
    context.has_human_approval == true
};

// Block first-time target without approval
forbid (
    principal,
    action == PenTest::Action::"scan",
    resource
)
when {
    resource.is_first_scan == true &&
    context.has_human_approval != true
};

forbid (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.is_first_scan == true &&
    context.has_human_approval != true
};

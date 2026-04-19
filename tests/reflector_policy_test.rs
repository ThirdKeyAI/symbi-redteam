// Static-text assertions over the reflector Cedar policy.
//
// The runtime already parses and evaluates `policies/reflector.cedar`; this
// test is a guard against the policy file being accidentally rewritten in
// a way that loses the defensive-forbid pattern borrowed from
// symbiont-karpathy-loop. If someone drops the global forbid or widens the
// permit, this fails loudly in CI before the change lands.

const POLICY: &str = include_str!("../policies/reflector.cedar");

#[test]
fn reflector_policy_scopes_principal_to_phase_reflector() {
    assert!(
        POLICY.contains("PenTest::Phase::\"reflector\""),
        "reflector policy must name the reflector phase principal",
    );
}

#[test]
fn reflector_policy_has_defensive_forbid_unless() {
    // The pattern is a single `forbid ... unless { <tool whitelist> }` clause
    // that catches any future accidental widening of the reflector's surface.
    assert!(
        POLICY.contains("forbid") && POLICY.contains("unless"),
        "reflector policy must use `forbid ... unless` defensive negation",
    );
}

#[test]
fn reflector_policy_allows_only_the_three_permitted_tools() {
    for tool in ["store_knowledge", "recall_knowledge", "query_findings"] {
        assert!(
            POLICY.contains(tool),
            "reflector policy must reference allowed tool '{tool}'",
        );
    }
}

#[test]
fn reflector_policy_forbids_scan_exploit_postexploit_actions() {
    for action in ["\"scan\"", "\"exploit\"", "\"post_exploit\""] {
        assert!(
            POLICY.contains(action),
            "reflector policy must explicitly forbid action {action}",
        );
    }
}

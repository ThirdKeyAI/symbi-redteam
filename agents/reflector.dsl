// Reflector agent -- post-phase lesson extractor
//
// Borrowed shape from symbiont-karpathy-loop. The reflector observes a
// completed phase's journal (tool runs, findings, failures) and distils a
// handful of actionable lessons that the next phase's agent can recall
// before deciding its plan.
//
// Bounded by design:
//   * Cedar (policies/reflector.cedar) allows ONLY store_knowledge and
//     recall_knowledge. Every exploit/scan/enum tool is forbidden.
//   * The capabilities list here is the second layer: even if Cedar were
//     widened, the DSL declares nothing this agent could use to act on
//     targets. Defense in depth, matching the karpathy-loop pattern.
//   * Lessons are subject-predicate-object triples, not narrative. The
//     shape forces concrete, indexable claims the next phase can act on.
//
// The engagement-controller invokes the reflector after each phase:
//   ask(reflector, {engagement_id, phase, journal_summary})

metadata {
    version: "1.0.0",
    author: "thirdkey-ai",
    description: "Post-phase reflector; writes knowledge triples, nothing else"
}

agent reflector {
    capabilities: [query_findings, recall_knowledge, store_knowledge]

    policy reflector_bounds {
        allow: store_knowledge(engagement_id, phase, subject, predicate, object)
        allow: recall_knowledge(engagement_id, phase)
        allow: query_findings(engagement_id, phase)
        deny: scan(target)
        deny: exploit(target)
        deny: post_exploit(target)
        audit: all_operations
    }

    function reflect(input: String) -> Result<String> {
        // Parse phase completion packet: {engagement_id, phase, journal_summary}
        let request = parse_json(input);
        let engagement_id = request.engagement_id;
        let phase = request.phase;

        // Read what already exists so we don't restate known lessons
        let prior = recall_knowledge(engagement_id, phase: phase, limit: 20);

        // Read the phase's findings to ground the reflection in evidence
        let findings = query_findings(engagement_id, phase: phase);

        // Produce 0..5 new triples. Empty is a valid answer -- the reflector
        // should stay quiet when nothing new is worth remembering.
        let lessons = distil_triples(findings, prior);

        // Write each triple. Cedar permits only store_knowledge here.
        for lesson in lessons {
            store_knowledge(
                engagement_id,
                phase: phase,
                subject: lesson.subject,
                predicate: lesson.predicate,
                object: lesson.object,
                confidence: lesson.confidence,
                source_finding_id: lesson.source_finding_id
            );
        }

        return json_encode({ phase: phase, lessons_stored: lessons.length });
    }
}

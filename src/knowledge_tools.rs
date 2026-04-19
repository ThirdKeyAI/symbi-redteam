// =============================================================================
// knowledge_tools.rs -- MCP tools for the reflector/recall loop
//
// Two tools, written for a single idea borrowed from symbiont-karpathy-loop:
// a reflector agent observes a completed phase's journal and writes a
// handful of subject-predicate-object triples summarising what mattered;
// the next phase's agent recalls those triples before deciding its plan.
//
// Cedar enforces the split:
//   * reflector         -> permit store_knowledge + recall_knowledge
//   * every other phase -> permit recall_knowledge only
//
// The triple shape is deliberate. A reflector could write paragraphs, but
// the point is the *next* phase acting on the lesson, and bulleted triples
// are what fits cleanly into a capped prompt without token bloat.
// =============================================================================

use serde::{Deserialize, Serialize};

use crate::types::{validate_engagement_id, validate_safe_identifier, ToolDefinition, ToolError};

// ---------------------------------------------------------------------------
// store_knowledge -- reflector-only; record one triple
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct StoreKnowledgeInput {
    /// Engagement ID this lesson belongs to.
    pub engagement_id: String,
    /// Phase that produced the lesson: recon, enum, vuln, exploit, post_exploit, reporting.
    pub phase: String,
    /// Triple subject — the thing observed (e.g. `smb_null_session`).
    pub subject: String,
    /// Triple predicate — the relation (e.g. `enabled_on`).
    pub predicate: String,
    /// Triple object — the target/value (e.g. `10.0.2.15:445`).
    pub object: String,
    /// Confidence in the claim, 0.0 to 1.0.
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    /// Tool that surfaced the evidence, if attributable.
    #[serde(default)]
    pub source_tool: String,
    /// Finding this lesson was distilled from, if any.
    #[serde(default)]
    pub source_finding_id: String,
}

fn default_confidence() -> f64 {
    0.8
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoreKnowledgeOutput {
    pub knowledge_id: String,
    pub status: String,
}

pub fn store_knowledge(input: StoreKnowledgeInput) -> Result<StoreKnowledgeOutput, ToolError> {
    validate_engagement_id(&input.engagement_id)?;
    validate_safe_identifier(&input.phase, "phase")?;

    if input.subject.is_empty() || input.predicate.is_empty() || input.object.is_empty() {
        return Err(ToolError::InvalidInput(
            "subject, predicate, and object must all be non-empty".to_string(),
        ));
    }
    if !(0.0..=1.0).contains(&input.confidence) {
        return Err(ToolError::InvalidInput(format!(
            "confidence must be between 0.0 and 1.0, got {}",
            input.confidence
        )));
    }

    let db_path = std::env::var("SYMBI_DB_PATH")
        .unwrap_or_else(|_| "/app/.symbiont/data/redteam.db".to_string());
    let conn = crate::db::init_db(&db_path)
        .map_err(|e| ToolError::ExecutionFailed(format!("Database error: {e}")))?;

    let k = crate::db::NewKnowledge {
        engagement_id: input.engagement_id,
        phase: input.phase,
        subject: input.subject,
        predicate: input.predicate,
        object: input.object,
        confidence: input.confidence,
        source_tool: if input.source_tool.is_empty() {
            None
        } else {
            Some(input.source_tool)
        },
        source_finding_id: if input.source_finding_id.is_empty() {
            None
        } else {
            Some(input.source_finding_id)
        },
    };

    let knowledge_id = crate::db::insert_knowledge(&conn, &k)
        .map_err(|e| ToolError::ExecutionFailed(format!("Insert failed: {e}")))?;

    Ok(StoreKnowledgeOutput {
        knowledge_id,
        status: "stored".to_string(),
    })
}

// ---------------------------------------------------------------------------
// recall_knowledge -- all phase agents; read triples for the current engagement
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RecallKnowledgeInput {
    /// Engagement ID to recall lessons for.
    pub engagement_id: String,
    /// Optional phase filter (e.g. recall only recon lessons before starting enum).
    #[serde(default)]
    pub phase: String,
    /// Cap on returned triples. Keep small — this output lands in the prompt.
    #[serde(default = "default_recall_limit")]
    pub limit: usize,
}

fn default_recall_limit() -> usize {
    5
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecallKnowledgeOutput {
    pub count: usize,
    pub triples: Vec<serde_json::Value>,
    /// Pre-rendered bullet list, ready to splice into a prompt.
    pub bullets: String,
}

pub fn recall_knowledge(input: RecallKnowledgeInput) -> Result<RecallKnowledgeOutput, ToolError> {
    validate_engagement_id(&input.engagement_id)?;

    let phase = if input.phase.is_empty() {
        None
    } else {
        validate_safe_identifier(&input.phase, "phase")?;
        Some(input.phase.as_str())
    };

    let limit = input.limit.clamp(1, 50);

    let db_path = std::env::var("SYMBI_DB_PATH")
        .unwrap_or_else(|_| "/app/.symbiont/data/redteam.db".to_string());
    let conn = crate::db::init_db(&db_path)
        .map_err(|e| ToolError::ExecutionFailed(format!("Database error: {e}")))?;

    let rows = crate::db::recall_knowledge(&conn, &input.engagement_id, phase, limit)
        .map_err(|e| ToolError::ExecutionFailed(format!("Query failed: {e}")))?;

    let bullets = rows
        .iter()
        .map(|k| {
            format!(
                "- [{}] {} {} {} (confidence {:.2})",
                k.phase, k.subject, k.predicate, k.object, k.confidence
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let triples: Vec<serde_json::Value> = rows
        .iter()
        .map(|k| serde_json::to_value(k).unwrap_or_default())
        .collect();

    Ok(RecallKnowledgeOutput {
        count: triples.len(),
        triples,
        bullets,
    })
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

pub fn register_tools() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition::new("store_knowledge")
            .description(
                "Reflector-only. Record a subject-predicate-object lesson learned from a \
                 completed phase so the next phase can act on it. Cedar restricts this tool \
                 to the reflector principal.",
            )
            .input_schema::<StoreKnowledgeInput>()
            .cedar_resource("PenTest::KnowledgeStore")
            .cedar_actions(&["PenTest::Action::store_knowledge"]),
        ToolDefinition::new("recall_knowledge")
            .description(
                "Read back reflector-written lessons for the current engagement, optionally \
                 scoped to a producing phase. Returns structured triples plus a pre-rendered \
                 bullet list. Every phase agent may call this at phase entry.",
            )
            .input_schema::<RecallKnowledgeInput>()
            .cedar_resource("PenTest::KnowledgeStore")
            .cedar_actions(&["PenTest::Action::recall_knowledge"]),
    ]
}

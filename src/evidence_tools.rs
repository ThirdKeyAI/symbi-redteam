// =============================================================================
// evidence_tools.rs -- MCP tool definitions for evidence management
//
// These tools provide the shared evidence database interface that all
// phase agents use to store findings, record tool runs, and capture
// evidence artifacts. Cedar policies in evidence.cedar govern access.
// =============================================================================

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::types::{ToolDefinition, ToolError, validate_engagement_id, validate_confined_path};
use std::fs;
use std::path::Path;

// ---------------------------------------------------------------------------
// store_finding -- Insert a finding into the evidence database
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct StoreFindingInput {
    /// Engagement ID this finding belongs to
    pub engagement_id: String,
    /// Phase that produced this finding: recon, enum, vuln, exploit, post_exploit
    pub phase: String,
    /// Tool that produced this finding
    pub tool: String,
    /// Target IP address
    #[serde(default)]
    pub target_ip: String,
    /// Target port number
    #[serde(default)]
    pub target_port: Option<i32>,
    /// Service name (e.g., "ssh", "http", "smb")
    #[serde(default)]
    pub service: String,
    /// Severity: critical, high, medium, low, info
    pub severity: String,
    /// Short title describing the finding
    pub title: String,
    /// Detailed description of the finding
    #[serde(default)]
    pub description: String,
    /// Path to evidence file (screenshot, tool output)
    #[serde(default)]
    pub evidence_path: String,
    /// CVSS v3.1 score (0.0 - 10.0)
    #[serde(default)]
    pub cvss_score: Option<f64>,
    /// Comma-separated CVE IDs (e.g., "CVE-2024-1234,CVE-2024-5678")
    #[serde(default)]
    pub cve_ids: String,
    /// Remediation recommendation
    #[serde(default)]
    pub remediation: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoreFindingOutput {
    pub finding_id: String,
    pub audit_hash: String,
    pub status: String,
}

pub fn store_finding(input: StoreFindingInput) -> Result<StoreFindingOutput, ToolError> {
    validate_engagement_id(&input.engagement_id)?;

    let db_path = std::env::var("SYMBI_DB_PATH")
        .unwrap_or_else(|_| "/app/.symbiont/data/redteam.db".to_string());

    let conn = crate::db::init_db(&db_path)
        .map_err(|e| ToolError::ExecutionFailed(format!("Database error: {e}")))?;

    let finding = crate::db::NewFinding {
        engagement_id: input.engagement_id,
        phase: input.phase,
        tool: input.tool,
        target_ip: if input.target_ip.is_empty() { None } else { Some(input.target_ip) },
        target_port: input.target_port,
        service: if input.service.is_empty() { None } else { Some(input.service) },
        severity: input.severity,
        title: input.title,
        description: if input.description.is_empty() { None } else { Some(input.description) },
        evidence_path: if input.evidence_path.is_empty() { None } else { Some(input.evidence_path) },
        cvss_score: input.cvss_score,
        cve_ids: if input.cve_ids.is_empty() { None } else { Some(input.cve_ids) },
        remediation: if input.remediation.is_empty() { None } else { Some(input.remediation) },
        verified: false,
        false_positive: false,
    };

    let finding_id = crate::db::insert_finding(&conn, &finding)
        .map_err(|e| ToolError::ExecutionFailed(format!("Insert failed: {e}")))?;

    let audit_hash = hex_sha256(finding_id.as_bytes());

    Ok(StoreFindingOutput {
        finding_id,
        audit_hash,
        status: "stored".to_string(),
    })
}

// ---------------------------------------------------------------------------
// query_findings -- Query findings with optional filters
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct QueryFindingsInput {
    /// Engagement ID to query
    pub engagement_id: String,
    /// Optional phase filter: recon, enum, vuln, exploit, post_exploit
    #[serde(default)]
    pub phase: String,
    /// Optional severity filter: critical, high, medium, low, info
    #[serde(default)]
    pub severity: String,
    /// Optional tool filter
    #[serde(default)]
    pub tool: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryFindingsOutput {
    pub findings_count: usize,
    pub findings: Vec<serde_json::Value>,
}

pub fn query_findings(input: QueryFindingsInput) -> Result<QueryFindingsOutput, ToolError> {
    let db_path = std::env::var("SYMBI_DB_PATH")
        .unwrap_or_else(|_| "/app/.symbiont/data/redteam.db".to_string());

    let conn = crate::db::init_db(&db_path)
        .map_err(|e| ToolError::ExecutionFailed(format!("Database error: {e}")))?;

    let phase = if input.phase.is_empty() { None } else { Some(input.phase.as_str()) };
    let severity = if input.severity.is_empty() { None } else { Some(input.severity.as_str()) };
    let tool = if input.tool.is_empty() { None } else { Some(input.tool.as_str()) };

    let findings = crate::db::query_findings(&conn, &input.engagement_id, phase, severity, tool)
        .map_err(|e| ToolError::ExecutionFailed(format!("Query failed: {e}")))?;

    let findings_json: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| serde_json::to_value(f).unwrap_or_default())
        .collect();

    Ok(QueryFindingsOutput {
        findings_count: findings_json.len(),
        findings: findings_json,
    })
}

// ---------------------------------------------------------------------------
// search_similar_findings -- Semantic search via LanceDB embeddings
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SearchSimilarInput {
    /// Natural language description to search for
    pub query: String,
    /// Maximum number of results to return
    #[serde(default = "default_search_limit")]
    pub limit: usize,
    /// Optional engagement_id filter
    #[serde(default)]
    pub engagement_id: String,
}

fn default_search_limit() -> usize {
    10
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchSimilarOutput {
    pub results_count: usize,
    pub results: Vec<serde_json::Value>,
}

pub fn search_similar_findings(input: SearchSimilarInput) -> Result<SearchSimilarOutput, ToolError> {
    if !input.engagement_id.is_empty() {
        validate_engagement_id(&input.engagement_id)?;
    }

    let lance_path = std::env::var("SYMBI_LANCE_PATH")
        .unwrap_or_else(|_| "/app/.symbiont/data/lance".to_string());

    let rt = tokio::runtime::Handle::try_current()
        .map_err(|e| ToolError::ExecutionFailed(format!("No async runtime: {e}")))?;

    let results = rt.block_on(async {
        use lancedb::query::{QueryBase, ExecutableQuery};
        use futures::TryStreamExt;

        let db = lancedb::connect(&lance_path).execute().await
            .map_err(|e| ToolError::ExecutionFailed(format!("LanceDB connect failed: {e}")))?;

        let table = db.open_table("redteam_embeddings").execute().await
            .map_err(|e| ToolError::ExecutionFailed(format!("Table open failed: {e}")))?;

        // Escape LIKE wildcards and single quotes for safe filter construction.
        let safe_query = input.query
            .replace('\'', "''")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let filter = if input.engagement_id.is_empty() {
            format!("text LIKE '%{safe_query}%'")
        } else {
            let safe_eid = input.engagement_id.replace('\'', "''");
            format!(
                "engagement_id = '{safe_eid}' AND text LIKE '%{safe_query}%'",
            )
        };

        let query_results = table
            .query()
            .only_if(filter)
            .limit(input.limit)
            .execute()
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Search execute failed: {e}")))?;

        let batches: Vec<arrow_array::RecordBatch> = query_results
            .try_collect()
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Collect failed: {e}")))?;

        let mut results = Vec::new();
        for batch in batches {
            for row_idx in 0..batch.num_rows() {
                let mut row = serde_json::Map::new();
                for (col_idx, field) in batch.schema().fields().iter().enumerate() {
                    let col = batch.column(col_idx);
                    let val = arrow_array_to_json_value(col, row_idx);
                    row.insert(field.name().clone(), val);
                }
                results.push(serde_json::Value::Object(row));
            }
        }

        Ok::<Vec<serde_json::Value>, ToolError>(results)
    })?;

    Ok(SearchSimilarOutput {
        results_count: results.len(),
        results,
    })
}

/// Convert an Arrow array element at a given index to a JSON value.
fn arrow_array_to_json_value(col: &std::sync::Arc<dyn arrow_array::Array>, idx: usize) -> serde_json::Value {
    if col.is_null(idx) {
        return serde_json::Value::Null;
    }
    if let Some(arr) = col.as_any().downcast_ref::<arrow_array::StringArray>() {
        serde_json::Value::String(arr.value(idx).to_string())
    } else if let Some(arr) = col.as_any().downcast_ref::<arrow_array::Float64Array>() {
        serde_json::json!(arr.value(idx))
    } else if let Some(arr) = col.as_any().downcast_ref::<arrow_array::Int64Array>() {
        serde_json::json!(arr.value(idx))
    } else if let Some(arr) = col.as_any().downcast_ref::<arrow_array::Float32Array>() {
        serde_json::json!(arr.value(idx))
    } else if let Some(arr) = col.as_any().downcast_ref::<arrow_array::Int32Array>() {
        serde_json::json!(arr.value(idx))
    } else if let Some(arr) = col.as_any().downcast_ref::<arrow_array::BooleanArray>() {
        serde_json::json!(arr.value(idx))
    } else {
        serde_json::Value::String(format!("{:?}", col))
    }
}

// ---------------------------------------------------------------------------
// store_tool_run -- Record a tool execution with Cedar decision
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct StoreToolRunInput {
    /// Engagement ID
    pub engagement_id: String,
    /// Associated finding ID (optional)
    #[serde(default)]
    pub finding_id: String,
    /// Tool name
    pub tool: String,
    /// Exact command executed
    pub command: String,
    /// JSON arguments passed to the tool
    #[serde(default)]
    pub arguments: String,
    /// Process exit code
    #[serde(default)]
    pub exit_code: Option<i32>,
    /// Execution duration in milliseconds
    #[serde(default)]
    pub duration_ms: Option<i64>,
    /// Path to output file
    #[serde(default)]
    pub output_file: String,
    /// Cedar decision: "allow" or "deny"
    #[serde(default)]
    pub cedar_decision: String,
    /// Cedar policy that matched
    #[serde(default)]
    pub cedar_policy: String,
    /// Human approver identity (if escalated)
    #[serde(default)]
    pub approved_by: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoreToolRunOutput {
    pub run_id: String,
    pub status: String,
}

pub fn store_tool_run(input: StoreToolRunInput) -> Result<StoreToolRunOutput, ToolError> {
    validate_engagement_id(&input.engagement_id)?;

    let db_path = std::env::var("SYMBI_DB_PATH")
        .unwrap_or_else(|_| "/app/.symbiont/data/redteam.db".to_string());

    let conn = crate::db::init_db(&db_path)
        .map_err(|e| ToolError::ExecutionFailed(format!("Database error: {e}")))?;

    let tool_run = crate::db::NewToolRun {
        engagement_id: input.engagement_id,
        finding_id: if input.finding_id.is_empty() { None } else { Some(input.finding_id) },
        tool: input.tool,
        command: input.command,
        arguments: if input.arguments.is_empty() { None } else { Some(input.arguments) },
        exit_code: input.exit_code,
        duration_ms: input.duration_ms,
        output_file: if input.output_file.is_empty() { None } else { Some(input.output_file) },
        cedar_decision: if input.cedar_decision.is_empty() { None } else { Some(input.cedar_decision) },
        cedar_policy: if input.cedar_policy.is_empty() { None } else { Some(input.cedar_policy) },
        approved_by: if input.approved_by.is_empty() { None } else { Some(input.approved_by) },
    };

    let run_id = crate::db::insert_tool_run(&conn, &tool_run)
        .map_err(|e| ToolError::ExecutionFailed(format!("Insert failed: {e}")))?;

    Ok(StoreToolRunOutput {
        run_id,
        status: "recorded".to_string(),
    })
}

// ---------------------------------------------------------------------------
// verify_finding -- Mark a finding as verified by the validate agent
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct VerifyFindingInput {
    /// UUID of the finding being verified
    pub finding_id: String,
    /// Free-form justification (evidence reviewed, reproduction notes, etc.)
    pub rationale: String,
    /// Identity of the verifier (agent name or human operator)
    pub verifier: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyFindingOutput {
    pub verification_id: String,
    pub audit_hash: String,
    pub status: String,
}

pub fn verify_finding(input: VerifyFindingInput) -> Result<VerifyFindingOutput, ToolError> {
    record_verdict(input.finding_id, crate::db::Verdict::Verified, input.rationale, input.verifier)
}

// ---------------------------------------------------------------------------
// mark_false_positive -- Suppress a finding the validate agent rejected
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MarkFalsePositiveInput {
    /// UUID of the finding being marked
    pub finding_id: String,
    /// Why the finding is a false positive (verification evidence)
    pub rationale: String,
    /// Identity of the verifier (agent name or human operator)
    pub verifier: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MarkFalsePositiveOutput {
    pub verification_id: String,
    pub audit_hash: String,
    pub status: String,
}

pub fn mark_false_positive(input: MarkFalsePositiveInput) -> Result<MarkFalsePositiveOutput, ToolError> {
    let out = record_verdict(input.finding_id, crate::db::Verdict::FalsePositive, input.rationale, input.verifier)?;
    Ok(MarkFalsePositiveOutput {
        verification_id: out.verification_id,
        audit_hash: out.audit_hash,
        status: out.status,
    })
}

fn record_verdict(
    finding_id: String,
    verdict: crate::db::Verdict,
    rationale: String,
    verifier: String,
) -> Result<VerifyFindingOutput, ToolError> {
    if finding_id.trim().is_empty() {
        return Err(ToolError::InvalidInput("finding_id is required".into()));
    }
    if rationale.trim().is_empty() {
        return Err(ToolError::InvalidInput("rationale is required".into()));
    }
    if verifier.trim().is_empty() {
        return Err(ToolError::InvalidInput("verifier is required".into()));
    }

    let db_path = std::env::var("SYMBI_DB_PATH")
        .unwrap_or_else(|_| "/app/.symbiont/data/redteam.db".to_string());

    let mut conn = crate::db::init_db(&db_path)
        .map_err(|e| ToolError::ExecutionFailed(format!("Database error: {e}")))?;

    let new = crate::db::NewVerification { finding_id: finding_id.clone(), verdict, rationale, verifier };
    let verification_id = crate::db::record_verification(&mut conn, &new)
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                ToolError::InvalidInput(format!("finding_id '{finding_id}' not found"))
            }
            other => ToolError::ExecutionFailed(format!("Verification failed: {other}")),
        })?;

    let audit_hash = hex_sha256(verification_id.as_bytes());
    Ok(VerifyFindingOutput {
        verification_id,
        audit_hash,
        status: "verified".to_string(),
    })
}

// ---------------------------------------------------------------------------
// capture_evidence -- Screenshot/output archival with integrity hash
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CaptureEvidenceInput {
    /// Engagement ID
    pub engagement_id: String,
    /// Source file path to archive (tool output, screenshot, etc.)
    pub source_path: String,
    /// Description of the evidence
    #[serde(default)]
    pub description: String,
    /// Associated finding ID (optional)
    #[serde(default)]
    pub finding_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaptureEvidenceOutput {
    pub evidence_path: String,
    pub sha256_hash: String,
    pub size_bytes: u64,
    pub status: String,
}

pub fn capture_evidence(input: CaptureEvidenceInput) -> Result<CaptureEvidenceOutput, ToolError> {
    // Validate engagement_id to prevent directory traversal
    validate_engagement_id(&input.engagement_id)?;

    // Confine source_path under /app/.symbiont/ to prevent reading arbitrary files
    let safe_source = validate_confined_path(&input.source_path, "/app/.symbiont/")?;

    let evidence_dir = format!("/app/.symbiont/evidence/{}", input.engagement_id);

    // Create evidence directory if it doesn't exist
    fs::create_dir_all(&evidence_dir)
        .map_err(|e| ToolError::ExecutionFailed(format!("Failed to create evidence dir: {e}")))?;

    // Read source file directly (no separate existence check — avoids TOCTOU race)
    let content = fs::read(&safe_source)
        .map_err(|e| ToolError::ExecutionFailed(format!("Failed to read source '{}': {e}", safe_source)))?;

    let hash = hex_sha256(&content);
    let size = content.len() as u64;

    // Generate evidence filename with hash prefix for deduplication
    let source_name = Path::new(&safe_source)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "evidence".to_string());
    let evidence_filename = format!("{}_{}", &hash[..8], source_name);
    let evidence_path = format!("{}/{}", evidence_dir, evidence_filename);

    // Write from already-read content instead of re-reading (avoids TOCTOU)
    fs::write(&evidence_path, &content)
        .map_err(|e| ToolError::ExecutionFailed(format!("Failed to write evidence: {e}")))?;

    Ok(CaptureEvidenceOutput {
        evidence_path,
        sha256_hash: hash,
        size_bytes: size,
        status: "captured".to_string(),
    })
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

pub fn register_tools() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition::new("store_finding")
            .description("Store a security finding in the evidence database with severity, \
                          CVE references, and remediation guidance. All phase agents use this \
                          to record discovered vulnerabilities.")
            .input_schema::<StoreFindingInput>()
            .cedar_resource("PenTest::EvidenceStore")
            .cedar_actions(&["PenTest::Action::store_evidence"]),
        ToolDefinition::new("query_findings")
            .description("Query findings from the evidence database with optional filters by \
                          phase, severity, and tool. Returns structured finding records.")
            .input_schema::<QueryFindingsInput>()
            .cedar_resource("PenTest::EvidenceStore")
            .cedar_actions(&["PenTest::Action::query_evidence"]),
        ToolDefinition::new("search_similar_findings")
            .description("Search for semantically similar findings using vector embeddings. \
                          Useful for correlating findings across tools and engagements, and \
                          for retest comparison.")
            .input_schema::<SearchSimilarInput>()
            .cedar_resource("PenTest::EvidenceStore")
            .cedar_actions(&["PenTest::Action::query_evidence"]),
        ToolDefinition::new("store_tool_run")
            .description("Record a tool execution in the audit trail, including the exact \
                          command, Cedar policy decision, exit code, and approver identity.")
            .input_schema::<StoreToolRunInput>()
            .cedar_resource("PenTest::EvidenceStore")
            .cedar_actions(&["PenTest::Action::store_evidence"]),
        ToolDefinition::new("capture_evidence")
            .description("Archive a tool output file or screenshot to the tamper-evident \
                          evidence store. Computes SHA-256 hash for integrity verification.")
            .input_schema::<CaptureEvidenceInput>()
            .cedar_resource("PenTest::EvidenceStore")
            .cedar_actions(&["PenTest::Action::store_evidence"]),
        ToolDefinition::new("verify_finding")
            .description("Mark a finding as verified after reviewing its evidence. Reserved \
                          for the validate agent: structurally denied to all other principals \
                          by validation.cedar. Records an audit row in finding_verifications.")
            .input_schema::<VerifyFindingInput>()
            .cedar_resource("PenTest::EvidenceStore")
            .cedar_actions(&["PenTest::Action::verify_evidence"]),
        ToolDefinition::new("mark_false_positive")
            .description("Suppress a finding as a false positive after reviewing its evidence. \
                          Reserved for the validate agent: structurally denied to all other \
                          principals by validation.cedar. Sets verified = TRUE and \
                          false_positive = TRUE atomically.")
            .input_schema::<MarkFalsePositiveInput>()
            .cedar_resource("PenTest::EvidenceStore")
            .cedar_actions(&["PenTest::Action::verify_evidence"]),
    ]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

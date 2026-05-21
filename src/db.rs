// =============================================================================
// db.rs -- SQLite database layer for the pen test evidence database
//
// Provides typed CRUD operations for engagements, findings, tool runs,
// and retests. All schema migrations are embedded at compile time via
// include_str!. WAL mode and foreign keys are enabled on every connection.
// =============================================================================

use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Embedded schema applied on every `init_db` call (all statements are
/// CREATE IF NOT EXISTS, so re-running is safe).
const SCHEMA_SQL: &str = include_str!("../db/schema.sql");

// =============================================================================
// Helpers
// =============================================================================

/// Return the lowercase hex-encoded SHA-256 digest of `data`.
pub fn hex_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// =============================================================================
// Initialization
// =============================================================================

/// Open (or create) a SQLite database at `db_path`, enable WAL journal mode
/// and foreign key enforcement, then apply the embedded schema.
pub fn init_db(db_path: &str) -> SqlResult<Connection> {
    let conn = Connection::open(db_path)?;

    // WAL gives us concurrent readers while a single writer proceeds.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    // Enforce referential integrity at the connection level.
    conn.pragma_update(None, "foreign_keys", "ON")?;

    conn.execute_batch(SCHEMA_SQL)?;

    Ok(conn)
}

// =============================================================================
// Engagement
// =============================================================================

/// A row from the `engagements` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Engagement {
    pub id: String,
    pub client: String,
    pub scope_hash: String,
    pub start_date: String,
    pub end_date: String,
    pub status: String,
    pub roa_hash: Option<String>,
    pub created_at: Option<String>,
}

/// Create a new engagement. A UUID v4 is generated for the primary key and
/// the SHA-256 of `scope_toml` is stored as `scope_hash`.
///
/// Returns the generated engagement id.
pub fn create_engagement(
    conn: &Connection,
    client: &str,
    scope_toml: &str,
    start_date: &str,
    end_date: &str,
) -> SqlResult<String> {
    let id = Uuid::new_v4().to_string();
    let scope_hash = hex_sha256(scope_toml.as_bytes());

    conn.execute(
        "INSERT INTO engagements (id, client, scope_hash, start_date, end_date, status)
         VALUES (?1, ?2, ?3, ?4, ?5, 'planning')",
        params![id, client, scope_hash, start_date, end_date],
    )?;

    Ok(id)
}

/// Fetch a single engagement by id, or `None` if it does not exist.
pub fn get_engagement(conn: &Connection, id: &str) -> SqlResult<Option<Engagement>> {
    let mut stmt = conn.prepare(
        "SELECT id, client, scope_hash, start_date, end_date, status, roa_hash, created_at
         FROM engagements WHERE id = ?1",
    )?;

    let mut rows = stmt.query_map(params![id], |row| {
        Ok(Engagement {
            id: row.get(0)?,
            client: row.get(1)?,
            scope_hash: row.get(2)?,
            start_date: row.get(3)?,
            end_date: row.get(4)?,
            status: row.get(5)?,
            roa_hash: row.get(6)?,
            created_at: row.get(7)?,
        })
    })?;

    match rows.next() {
        Some(row) => Ok(Some(row?)),
        None => Ok(None),
    }
}

/// Update the status of an engagement. Returns the number of rows affected
/// (0 if the id was not found, 1 on success).
pub fn update_engagement_status(
    conn: &Connection,
    id: &str,
    status: &str,
) -> SqlResult<usize> {
    conn.execute(
        "UPDATE engagements SET status = ?1 WHERE id = ?2",
        params![status, id],
    )
}

// =============================================================================
// Finding
// =============================================================================

/// A row from the `findings` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub engagement_id: String,
    pub phase: String,
    pub tool: String,
    pub target_ip: Option<String>,
    pub target_port: Option<i32>,
    pub service: Option<String>,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub evidence_path: Option<String>,
    pub cvss_score: Option<f64>,
    pub cve_ids: Option<String>,
    pub remediation: Option<String>,
    pub verified: bool,
    pub false_positive: bool,
    pub created_at: Option<String>,
    pub audit_hash: Option<String>,
}

/// Input struct for creating a new finding (excludes auto-generated fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewFinding {
    pub engagement_id: String,
    pub phase: String,
    pub tool: String,
    pub target_ip: Option<String>,
    pub target_port: Option<i32>,
    pub service: Option<String>,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub evidence_path: Option<String>,
    pub cvss_score: Option<f64>,
    pub cve_ids: Option<String>,
    pub remediation: Option<String>,
    pub verified: bool,
    pub false_positive: bool,
}

/// Compute the audit hash for a finding from its key identifying fields.
/// This allows detection of duplicate or tampered records.
fn compute_audit_hash(f: &NewFinding) -> String {
    let payload = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        f.engagement_id,
        f.phase,
        f.tool,
        f.target_ip.as_deref().unwrap_or(""),
        f.target_port.map_or(String::new(), |p| p.to_string()),
        f.severity,
        f.title,
    );
    hex_sha256(payload.as_bytes())
}

/// Insert a new finding. Generates a UUID v4 primary key and computes the
/// `audit_hash` from key fields. Returns the generated finding id.
pub fn insert_finding(conn: &Connection, f: &NewFinding) -> SqlResult<String> {
    let id = Uuid::new_v4().to_string();
    let audit_hash = compute_audit_hash(f);

    conn.execute(
        "INSERT INTO findings
            (id, engagement_id, phase, tool, target_ip, target_port, service,
             severity, title, description, evidence_path, cvss_score, cve_ids,
             remediation, verified, false_positive, audit_hash)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
        params![
            id,
            f.engagement_id,
            f.phase,
            f.tool,
            f.target_ip,
            f.target_port,
            f.service,
            f.severity,
            f.title,
            f.description,
            f.evidence_path,
            f.cvss_score,
            f.cve_ids,
            f.remediation,
            f.verified,
            f.false_positive,
            audit_hash,
        ],
    )?;

    Ok(id)
}

/// Query findings for an engagement with optional filters on phase, severity,
/// and tool. Builds the WHERE clause dynamically; only non-`None` filters are
/// applied.
pub fn query_findings(
    conn: &Connection,
    engagement_id: &str,
    phase: Option<&str>,
    severity: Option<&str>,
    tool: Option<&str>,
) -> SqlResult<Vec<Finding>> {
    let mut sql = String::from(
        "SELECT id, engagement_id, phase, tool, target_ip, target_port, service,
                severity, title, description, evidence_path, cvss_score, cve_ids,
                remediation, verified, false_positive, created_at, audit_hash
         FROM findings WHERE engagement_id = ?",
    );

    let mut bind_values: Vec<Box<dyn rusqlite::types::ToSql>> =
        vec![Box::new(engagement_id.to_owned())];

    if let Some(p) = phase {
        sql.push_str(" AND phase = ?");
        bind_values.push(Box::new(p.to_owned()));
    }
    if let Some(s) = severity {
        sql.push_str(" AND severity = ?");
        bind_values.push(Box::new(s.to_owned()));
    }
    if let Some(t) = tool {
        sql.push_str(" AND tool = ?");
        bind_values.push(Box::new(t.to_owned()));
    }

    sql.push_str(" ORDER BY created_at DESC");

    let params_refs: Vec<&dyn rusqlite::types::ToSql> =
        bind_values.iter().map(|b| b.as_ref()).collect();

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_refs.as_slice(), |row| {
        Ok(Finding {
            id: row.get(0)?,
            engagement_id: row.get(1)?,
            phase: row.get(2)?,
            tool: row.get(3)?,
            target_ip: row.get(4)?,
            target_port: row.get(5)?,
            service: row.get(6)?,
            severity: row.get(7)?,
            title: row.get(8)?,
            description: row.get(9)?,
            evidence_path: row.get(10)?,
            cvss_score: row.get(11)?,
            cve_ids: row.get(12)?,
            remediation: row.get(13)?,
            verified: row.get(14)?,
            false_positive: row.get(15)?,
            created_at: row.get(16)?,
            audit_hash: row.get(17)?,
        })
    })?;

    rows.collect()
}

/// Count findings in a specific phase for an engagement.
pub fn count_findings_by_phase(
    conn: &Connection,
    engagement_id: &str,
    phase: &str,
) -> SqlResult<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM findings WHERE engagement_id = ?1 AND phase = ?2",
        params![engagement_id, phase],
        |row| row.get(0),
    )
}

/// Count findings with severity `critical` or `high` that have not been
/// verified (`verified = FALSE`). Useful for dashboards and gate decisions.
pub fn count_unverified_critical_high(
    conn: &Connection,
    engagement_id: &str,
) -> SqlResult<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM findings
         WHERE engagement_id = ?1
           AND severity IN ('critical', 'high')
           AND verified = FALSE",
        params![engagement_id],
        |row| row.get(0),
    )
}

// =============================================================================
// Finding Verification
// =============================================================================

/// Verdict recorded by the validate agent against a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Verified,
    FalsePositive,
}

impl Verdict {
    fn as_db_str(self) -> &'static str {
        match self {
            Verdict::Verified => "verified",
            Verdict::FalsePositive => "false_positive",
        }
    }
}

/// Audit record describing a verification decision against a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewVerification {
    pub finding_id: String,
    pub verdict: Verdict,
    pub rationale: String,
    pub verifier: String,
}

/// Atomically apply a verification verdict: record an audit row in
/// `finding_verifications` and flip the corresponding flags on `findings`.
/// `verified = TRUE` is set for both verdicts so the unverified-critical-high
/// gate clears; `false_positive = TRUE` is set only for FalsePositive verdicts.
pub fn record_verification(
    conn: &mut Connection,
    v: &NewVerification,
) -> SqlResult<String> {
    let id = Uuid::new_v4().to_string();
    let tx = conn.transaction()?;

    let updated = tx.execute(
        "UPDATE findings
         SET verified = TRUE,
             false_positive = CASE WHEN ?1 = 'false_positive' THEN TRUE ELSE false_positive END
         WHERE id = ?2",
        params![v.verdict.as_db_str(), v.finding_id],
    )?;
    if updated == 0 {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }

    tx.execute(
        "INSERT INTO finding_verifications
            (id, finding_id, verdict, rationale, verifier)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, v.finding_id, v.verdict.as_db_str(), v.rationale, v.verifier],
    )?;

    tx.commit()?;
    Ok(id)
}

// =============================================================================
// Tool Run
// =============================================================================

/// A row from the `tool_runs` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRun {
    pub id: String,
    pub engagement_id: String,
    pub finding_id: Option<String>,
    pub tool: String,
    pub command: String,
    pub arguments: Option<String>,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<i64>,
    pub output_file: Option<String>,
    pub cedar_decision: Option<String>,
    pub cedar_policy: Option<String>,
    pub approved_by: Option<String>,
    pub created_at: Option<String>,
}

/// Input struct for recording a new tool run (excludes auto-generated fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewToolRun {
    pub engagement_id: String,
    pub finding_id: Option<String>,
    pub tool: String,
    pub command: String,
    pub arguments: Option<String>,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<i64>,
    pub output_file: Option<String>,
    pub cedar_decision: Option<String>,
    pub cedar_policy: Option<String>,
    pub approved_by: Option<String>,
}

/// Insert a tool run record. Generates a UUID v4 primary key.
/// Returns the generated tool run id.
pub fn insert_tool_run(conn: &Connection, r: &NewToolRun) -> SqlResult<String> {
    let id = Uuid::new_v4().to_string();

    conn.execute(
        "INSERT INTO tool_runs
            (id, engagement_id, finding_id, tool, command, arguments,
             exit_code, duration_ms, output_file, cedar_decision,
             cedar_policy, approved_by)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![
            id,
            r.engagement_id,
            r.finding_id,
            r.tool,
            r.command,
            r.arguments,
            r.exit_code,
            r.duration_ms,
            r.output_file,
            r.cedar_decision,
            r.cedar_policy,
            r.approved_by,
        ],
    )?;

    Ok(id)
}

/// Fetch tool runs for an engagement, optionally filtered by tool name.
pub fn get_tool_runs(
    conn: &Connection,
    engagement_id: &str,
    tool: Option<&str>,
) -> SqlResult<Vec<ToolRun>> {
    let mut sql = String::from(
        "SELECT id, engagement_id, finding_id, tool, command, arguments,
                exit_code, duration_ms, output_file, cedar_decision,
                cedar_policy, approved_by, created_at
         FROM tool_runs WHERE engagement_id = ?",
    );

    let mut bind_values: Vec<Box<dyn rusqlite::types::ToSql>> =
        vec![Box::new(engagement_id.to_owned())];

    if let Some(t) = tool {
        sql.push_str(" AND tool = ?");
        bind_values.push(Box::new(t.to_owned()));
    }

    sql.push_str(" ORDER BY created_at DESC");

    let params_refs: Vec<&dyn rusqlite::types::ToSql> =
        bind_values.iter().map(|b| b.as_ref()).collect();

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_refs.as_slice(), |row| {
        Ok(ToolRun {
            id: row.get(0)?,
            engagement_id: row.get(1)?,
            finding_id: row.get(2)?,
            tool: row.get(3)?,
            command: row.get(4)?,
            arguments: row.get(5)?,
            exit_code: row.get(6)?,
            duration_ms: row.get(7)?,
            output_file: row.get(8)?,
            cedar_decision: row.get(9)?,
            cedar_policy: row.get(10)?,
            approved_by: row.get(11)?,
            created_at: row.get(12)?,
        })
    })?;

    rows.collect()
}

// =============================================================================
// Retest
// =============================================================================

/// A row from the `retests` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Retest {
    pub id: String,
    pub engagement_id: String,
    pub baseline_engagement_id: String,
    pub finding_id: String,
    pub baseline_finding_id: String,
    pub status: String,
    pub notes: Option<String>,
    pub created_at: Option<String>,
}

/// Insert a retest record linking a current finding to its baseline.
/// Generates a UUID v4 primary key. Returns the generated retest id.
pub fn insert_retest(
    conn: &Connection,
    engagement_id: &str,
    baseline_engagement_id: &str,
    finding_id: &str,
    baseline_finding_id: &str,
    status: &str,
    notes: Option<&str>,
) -> SqlResult<String> {
    let id = Uuid::new_v4().to_string();

    conn.execute(
        "INSERT INTO retests
            (id, engagement_id, baseline_engagement_id, finding_id,
             baseline_finding_id, status, notes)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            id,
            engagement_id,
            baseline_engagement_id,
            finding_id,
            baseline_finding_id,
            status,
            notes,
        ],
    )?;

    Ok(id)
}

/// Fetch all retests for an engagement.
pub fn get_retests(conn: &Connection, engagement_id: &str) -> SqlResult<Vec<Retest>> {
    let mut stmt = conn.prepare(
        "SELECT id, engagement_id, baseline_engagement_id, finding_id,
                baseline_finding_id, status, notes, created_at
         FROM retests WHERE engagement_id = ?1
         ORDER BY created_at DESC",
    )?;

    let rows = stmt.query_map(params![engagement_id], |row| {
        Ok(Retest {
            id: row.get(0)?,
            engagement_id: row.get(1)?,
            baseline_engagement_id: row.get(2)?,
            finding_id: row.get(3)?,
            baseline_finding_id: row.get(4)?,
            status: row.get(5)?,
            notes: row.get(6)?,
            created_at: row.get(7)?,
        })
    })?;

    rows.collect()
}

// =============================================================================
// Knowledge
//
// Reflector-authored lessons from completed phases. Subject-predicate-object
// triples deliberately — freeform notes would be easier for an LLM to
// produce but harder for the *next* phase to act on. The triple shape means
// the agent that recalls it gets structured, indexable claims.
// =============================================================================

/// A row from the `knowledge` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Knowledge {
    pub id: String,
    pub engagement_id: String,
    pub phase: String,
    pub subject: String,
    pub predicate: String,
    pub object: String,
    pub confidence: f64,
    pub source_tool: Option<String>,
    pub source_finding_id: Option<String>,
    pub created_at: Option<String>,
}

/// Input struct for a new knowledge triple (excludes auto-generated fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewKnowledge {
    pub engagement_id: String,
    pub phase: String,
    pub subject: String,
    pub predicate: String,
    pub object: String,
    pub confidence: f64,
    pub source_tool: Option<String>,
    pub source_finding_id: Option<String>,
}

/// Insert a knowledge triple. Generates a UUID v4 primary key. No dedup —
/// if the reflector proposes the same triple twice, it lands twice.
/// Duplicates are cheap and make the reflector's behaviour auditable.
pub fn insert_knowledge(conn: &Connection, k: &NewKnowledge) -> SqlResult<String> {
    let id = Uuid::new_v4().to_string();

    conn.execute(
        "INSERT INTO knowledge
            (id, engagement_id, phase, subject, predicate, object,
             confidence, source_tool, source_finding_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            id,
            k.engagement_id,
            k.phase,
            k.subject,
            k.predicate,
            k.object,
            k.confidence,
            k.source_tool,
            k.source_finding_id,
        ],
    )?;

    Ok(id)
}

/// Recall knowledge triples for an engagement, optionally scoped to a phase
/// of interest. Most recent first; caller passes `limit` to cap prompt size.
pub fn recall_knowledge(
    conn: &Connection,
    engagement_id: &str,
    phase: Option<&str>,
    limit: usize,
) -> SqlResult<Vec<Knowledge>> {
    let mut sql = String::from(
        "SELECT id, engagement_id, phase, subject, predicate, object,
                confidence, source_tool, source_finding_id, created_at
         FROM knowledge WHERE engagement_id = ?",
    );

    let mut bind_values: Vec<Box<dyn rusqlite::types::ToSql>> =
        vec![Box::new(engagement_id.to_owned())];

    if let Some(p) = phase {
        sql.push_str(" AND phase = ?");
        bind_values.push(Box::new(p.to_owned()));
    }

    sql.push_str(" ORDER BY created_at DESC LIMIT ?");
    bind_values.push(Box::new(limit as i64));

    let params_refs: Vec<&dyn rusqlite::types::ToSql> =
        bind_values.iter().map(|b| b.as_ref()).collect();

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_refs.as_slice(), |row| {
        Ok(Knowledge {
            id: row.get(0)?,
            engagement_id: row.get(1)?,
            phase: row.get(2)?,
            subject: row.get(3)?,
            predicate: row.get(4)?,
            object: row.get(5)?,
            confidence: row.get(6)?,
            source_tool: row.get(7)?,
            source_finding_id: row.get(8)?,
            created_at: row.get(9)?,
        })
    })?;

    rows.collect()
}

// =============================================================================
// Engagement Summary
// =============================================================================

/// Aggregated statistics for an engagement, useful for dashboards and
/// automated gate decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementSummary {
    pub engagement_id: String,
    pub total_findings: i64,
    pub critical_count: i64,
    pub high_count: i64,
    pub medium_count: i64,
    pub low_count: i64,
    pub info_count: i64,
    pub total_tool_runs: i64,
    /// Distinct phases that have at least one finding.
    pub phases_with_findings: Vec<String>,
}

/// Build a summary of an engagement: finding counts by severity, total tool
/// runs, and which phases have findings.
pub fn get_engagement_summary(
    conn: &Connection,
    engagement_id: &str,
) -> SqlResult<EngagementSummary> {
    let total_findings: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings WHERE engagement_id = ?1",
        params![engagement_id],
        |row| row.get(0),
    )?;

    let severity_count = |sev: &str| -> SqlResult<i64> {
        conn.query_row(
            "SELECT COUNT(*) FROM findings WHERE engagement_id = ?1 AND severity = ?2",
            params![engagement_id, sev],
            |row| row.get(0),
        )
    };

    let critical_count = severity_count("critical")?;
    let high_count = severity_count("high")?;
    let medium_count = severity_count("medium")?;
    let low_count = severity_count("low")?;
    let info_count = severity_count("info")?;

    let total_tool_runs: i64 = conn.query_row(
        "SELECT COUNT(*) FROM tool_runs WHERE engagement_id = ?1",
        params![engagement_id],
        |row| row.get(0),
    )?;

    let mut stmt = conn.prepare(
        "SELECT DISTINCT phase FROM findings WHERE engagement_id = ?1 ORDER BY phase",
    )?;
    let phase_rows = stmt.query_map(params![engagement_id], |row| row.get::<_, String>(0))?;
    let phases_with_findings: Vec<String> = phase_rows.collect::<SqlResult<Vec<_>>>()?;

    Ok(EngagementSummary {
        engagement_id: engagement_id.to_owned(),
        total_findings,
        critical_count,
        high_count,
        medium_count,
        low_count,
        info_count,
        total_tool_runs,
        phases_with_findings,
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Create an in-memory database for testing.
    fn test_db() -> Connection {
        init_db(":memory:").expect("failed to init in-memory db")
    }

    #[test]
    fn test_hex_sha256() {
        let hash = hex_sha256(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_engagement_lifecycle() {
        let conn = test_db();

        let id = create_engagement(&conn, "Acme Corp", "[scope]\ncidrs=[\"10.0.0.0/8\"]", "2026-01-01", "2026-01-31")
            .expect("create_engagement failed");

        let eng = get_engagement(&conn, &id)
            .expect("get_engagement failed")
            .expect("engagement should exist");
        assert_eq!(eng.client, "Acme Corp");
        assert_eq!(eng.status, "planning");

        let updated = update_engagement_status(&conn, &id, "active")
            .expect("update_engagement_status failed");
        assert_eq!(updated, 1);

        let eng = get_engagement(&conn, &id).unwrap().unwrap();
        assert_eq!(eng.status, "active");
    }

    #[test]
    fn test_finding_insert_and_query() {
        let conn = test_db();
        let eid = create_engagement(&conn, "TestCo", "scope", "2026-01-01", "2026-02-01").unwrap();

        let new = NewFinding {
            engagement_id: eid.clone(),
            phase: "recon".into(),
            tool: "nmap".into(),
            target_ip: Some("10.0.0.1".into()),
            target_port: Some(22),
            service: Some("ssh".into()),
            severity: "high".into(),
            title: "Open SSH port".into(),
            description: None,
            evidence_path: None,
            cvss_score: Some(7.5),
            cve_ids: None,
            remediation: None,
            verified: false,
            false_positive: false,
        };

        let fid = insert_finding(&conn, &new).expect("insert_finding failed");
        assert!(!fid.is_empty());

        let all = query_findings(&conn, &eid, None, None, None).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].title, "Open SSH port");

        let by_phase = query_findings(&conn, &eid, Some("recon"), None, None).unwrap();
        assert_eq!(by_phase.len(), 1);

        let empty = query_findings(&conn, &eid, Some("exploit"), None, None).unwrap();
        assert!(empty.is_empty());

        let count = count_findings_by_phase(&conn, &eid, "recon").unwrap();
        assert_eq!(count, 1);

        let unverified = count_unverified_critical_high(&conn, &eid).unwrap();
        assert_eq!(unverified, 1);
    }

    #[test]
    fn test_tool_run_insert_and_query() {
        let conn = test_db();
        let eid = create_engagement(&conn, "TestCo", "scope", "2026-01-01", "2026-02-01").unwrap();

        let new_run = NewToolRun {
            engagement_id: eid.clone(),
            finding_id: None,
            tool: "nmap".into(),
            command: "nmap -sV 10.0.0.1".into(),
            arguments: Some("-sV".into()),
            exit_code: Some(0),
            duration_ms: Some(4500),
            output_file: Some("/tmp/scan.xml".into()),
            cedar_decision: Some("ALLOW".into()),
            cedar_policy: Some("scan-auth".into()),
            approved_by: None,
        };

        let rid = insert_tool_run(&conn, &new_run).unwrap();
        assert!(!rid.is_empty());

        let runs = get_tool_runs(&conn, &eid, None).unwrap();
        assert_eq!(runs.len(), 1);

        let filtered = get_tool_runs(&conn, &eid, Some("nmap")).unwrap();
        assert_eq!(filtered.len(), 1);

        let empty = get_tool_runs(&conn, &eid, Some("nikto")).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_retest_insert_and_query() {
        let conn = test_db();
        let eid1 = create_engagement(&conn, "TestCo", "scope1", "2026-01-01", "2026-01-31").unwrap();
        let eid2 = create_engagement(&conn, "TestCo", "scope2", "2026-03-01", "2026-03-31").unwrap();

        let f1 = insert_finding(&conn, &NewFinding {
            engagement_id: eid1.clone(),
            phase: "vuln".into(),
            tool: "nmap".into(),
            target_ip: Some("10.0.0.1".into()),
            target_port: Some(80),
            service: Some("http".into()),
            severity: "critical".into(),
            title: "RCE on web server".into(),
            description: None,
            evidence_path: None,
            cvss_score: Some(9.8),
            cve_ids: None,
            remediation: None,
            verified: true,
            false_positive: false,
        }).unwrap();

        let f2 = insert_finding(&conn, &NewFinding {
            engagement_id: eid2.clone(),
            phase: "vuln".into(),
            tool: "nmap".into(),
            target_ip: Some("10.0.0.1".into()),
            target_port: Some(80),
            service: Some("http".into()),
            severity: "critical".into(),
            title: "RCE on web server".into(),
            description: None,
            evidence_path: None,
            cvss_score: Some(9.8),
            cve_ids: None,
            remediation: None,
            verified: false,
            false_positive: false,
        }).unwrap();

        let rtid = insert_retest(&conn, &eid2, &eid1, &f2, &f1, "persistent", Some("still exploitable"))
            .unwrap();
        assert!(!rtid.is_empty());

        let retests = get_retests(&conn, &eid2).unwrap();
        assert_eq!(retests.len(), 1);
        assert_eq!(retests[0].status, "persistent");
        assert_eq!(retests[0].notes.as_deref(), Some("still exploitable"));
    }

    #[test]
    fn test_engagement_summary() {
        let conn = test_db();
        let eid = create_engagement(&conn, "SumCo", "scope", "2026-01-01", "2026-02-01").unwrap();

        let severities = ["critical", "high", "medium", "low", "info"];
        let phases = ["recon", "enum", "vuln", "exploit", "recon"];
        for (i, (sev, phase)) in severities.iter().zip(phases.iter()).enumerate() {
            insert_finding(&conn, &NewFinding {
                engagement_id: eid.clone(),
                phase: phase.to_string(),
                tool: "testtool".into(),
                target_ip: None,
                target_port: None,
                service: None,
                severity: sev.to_string(),
                title: format!("Finding {i}"),
                description: None,
                evidence_path: None,
                cvss_score: None,
                cve_ids: None,
                remediation: None,
                verified: false,
                false_positive: false,
            }).unwrap();
        }

        insert_tool_run(&conn, &NewToolRun {
            engagement_id: eid.clone(),
            finding_id: None,
            tool: "testtool".into(),
            command: "test".into(),
            arguments: None,
            exit_code: Some(0),
            duration_ms: None,
            output_file: None,
            cedar_decision: None,
            cedar_policy: None,
            approved_by: None,
        }).unwrap();

        let summary = get_engagement_summary(&conn, &eid).unwrap();
        assert_eq!(summary.total_findings, 5);
        assert_eq!(summary.critical_count, 1);
        assert_eq!(summary.high_count, 1);
        assert_eq!(summary.medium_count, 1);
        assert_eq!(summary.low_count, 1);
        assert_eq!(summary.info_count, 1);
        assert_eq!(summary.total_tool_runs, 1);
        // phases: enum, exploit, recon, vuln (sorted, distinct)
        assert_eq!(summary.phases_with_findings, vec!["enum", "exploit", "recon", "vuln"]);
    }
}

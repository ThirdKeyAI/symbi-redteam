//! Read layer for the viewer. Pure SQL against the pen-test schema
//! (`db/schema.sql`); nothing here mutates. User-supplied filter values are
//! always bound as parameters, never interpolated.

use anyhow::Result;
use rusqlite::Connection;
use serde::Deserialize;

/// Fixed page size for the findings list (also the hard cap — no endpoint
/// accepts a caller-supplied page size).
pub const DEFAULT_PAGE_SIZE: u32 = 50;

// ---------------------------------------------------------------------------
// Small SQL helpers
// ---------------------------------------------------------------------------

fn count(conn: &Connection, sql: &str, eid: &str) -> i64 {
    conn.query_row(sql, [eid], |r| r.get(0)).unwrap_or(0)
}

fn group_counts(conn: &Connection, sql: &str, eid: &str) -> Vec<(String, i64)> {
    let mut out = Vec::new();
    if let Ok(mut stmt) = conn.prepare(sql) {
        if let Ok(rows) =
            stmt.query_map([eid], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        {
            out = rows.filter_map(|r| r.ok()).collect();
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

pub struct Overview {
    pub client: String,
    pub status: String,
    pub created_at: String,
    pub start_date: String,
    pub end_date: String,
    pub total_findings: i64,
    pub verified: i64,
    pub false_positive: i64,
    pub pending: i64,
    pub tool_runs: i64,
    pub knowledge: i64,
    pub retests: i64,
    /// (severity, count) ordered critical→info.
    pub severity: Vec<(String, i64)>,
    /// (phase, count).
    pub phases: Vec<(String, i64)>,
    /// (cedar_decision, count) over tool_runs — the governance breakdown.
    pub cedar: Vec<(String, i64)>,
}

pub fn overview(conn: &Connection, eng: &str) -> Result<Overview> {
    let (client, status, created_at, start_date, end_date): (
        String,
        String,
        String,
        String,
        String,
    ) = conn
        .query_row(
            "SELECT client, status, created_at, start_date, end_date FROM engagements WHERE id = ?1",
            [eng],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap_or_else(|_| ("?".into(), "?".into(), "?".into(), "?".into(), "?".into()));

    // Order severity critical→info for the histogram.
    let order = ["critical", "high", "medium", "low", "info"];
    let mut sev = group_counts(
        conn,
        "SELECT severity, COUNT(*) FROM findings WHERE engagement_id = ?1 GROUP BY severity",
        eng,
    );
    sev.sort_by_key(|(s, _)| order.iter().position(|o| o == s).unwrap_or(99));

    let total = count(conn, "SELECT COUNT(*) FROM findings WHERE engagement_id = ?1", eng);
    let verified = count(
        conn,
        "SELECT COUNT(*) FROM findings WHERE engagement_id = ?1 AND verified = 1",
        eng,
    );
    let false_positive = count(
        conn,
        "SELECT COUNT(*) FROM findings WHERE engagement_id = ?1 AND false_positive = 1",
        eng,
    );

    Ok(Overview {
        client,
        status,
        created_at,
        start_date,
        end_date,
        total_findings: total,
        verified,
        false_positive,
        pending: (total - verified - false_positive).max(0),
        tool_runs: count(conn, "SELECT COUNT(*) FROM tool_runs WHERE engagement_id = ?1", eng),
        knowledge: count(conn, "SELECT COUNT(*) FROM knowledge WHERE engagement_id = ?1", eng),
        retests: count(conn, "SELECT COUNT(*) FROM retests WHERE engagement_id = ?1", eng),
        severity: sev,
        phases: group_counts(
            conn,
            "SELECT phase, COUNT(*) FROM findings WHERE engagement_id = ?1 GROUP BY phase",
            eng,
        ),
        cedar: group_counts(
            conn,
            "SELECT COALESCE(cedar_decision,'(none)'), COUNT(*) FROM tool_runs \
             WHERE engagement_id = ?1 GROUP BY cedar_decision",
            eng,
        ),
    })
}

// ---------------------------------------------------------------------------
// Findings table (filter + sort + paginate)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct FindingsQuery {
    pub phase: Option<String>,
    pub severity: Option<String>,
    pub tool: Option<String>,
    pub page: Option<u32>,
}

pub struct FindingRow {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub phase: String,
    pub tool: String,
    pub target_ip: Option<String>,
    pub target_port: Option<i64>,
    pub service: Option<String>,
    pub verified: bool,
    pub false_positive: bool,
    pub cvss_score: Option<f64>,
}

pub struct FindingsPage {
    pub rows: Vec<FindingRow>,
    pub total: i64,
    pub page: u32,
    pub page_size: u32,
    pub phases: Vec<String>,
    pub severities: Vec<String>,
    pub tools: Vec<String>,
}

/// Only whitelisted columns reach SQL via `add`; user input is always bound.
pub fn findings_page(conn: &Connection, eng: &str, q: &FindingsQuery) -> Result<FindingsPage> {
    let page = q.page.unwrap_or(0);
    let page_size = DEFAULT_PAGE_SIZE;
    let offset = (page as i64) * (page_size as i64);

    let mut where_sql = String::from("engagement_id = ?1");
    let mut params: Vec<String> = vec![eng.to_string()];
    let add = |col: &str, val: &Option<String>, params: &mut Vec<String>, where_sql: &mut String| {
        if let Some(v) = val.as_ref().filter(|v| !v.is_empty()) {
            params.push(v.clone());
            where_sql.push_str(&format!(" AND {col} = ?{}", params.len()));
        }
    };
    add("phase", &q.phase, &mut params, &mut where_sql);
    add("severity", &q.severity, &mut params, &mut where_sql);
    add("tool", &q.tool, &mut params, &mut where_sql);

    let pref: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

    let total: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM findings WHERE {where_sql}"),
        pref.as_slice(),
        |r| r.get(0),
    )?;

    // Severity-ordered, then CVSS desc, then id, for a stable, useful order.
    let sql = format!(
        "SELECT id, severity, title, phase, tool, target_ip, target_port, service,
                verified, false_positive, cvss_score
         FROM findings WHERE {where_sql}
         ORDER BY (CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 \
                   WHEN 'low' THEN 3 ELSE 4 END), COALESCE(cvss_score,0) DESC, id
         LIMIT {page_size} OFFSET {offset}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(pref.as_slice(), |r| {
            Ok(FindingRow {
                id: r.get(0)?,
                severity: r.get(1)?,
                title: r.get(2)?,
                phase: r.get(3)?,
                tool: r.get(4)?,
                target_ip: r.get(5)?,
                target_port: r.get(6)?,
                service: r.get(7)?,
                verified: r.get(8)?,
                false_positive: r.get(9)?,
                cvss_score: r.get(10)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();

    Ok(FindingsPage {
        rows,
        total,
        page,
        page_size,
        phases: distinct(conn, "phase", eng),
        severities: distinct(conn, "severity", eng),
        tools: distinct(conn, "tool", eng),
    })
}

fn distinct(conn: &Connection, col: &str, eid: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(mut stmt) = conn.prepare(&format!(
        "SELECT DISTINCT {col} FROM findings WHERE engagement_id = ?1 ORDER BY {col}"
    )) {
        if let Ok(rows) = stmt.query_map([eid], |r| r.get::<_, String>(0)) {
            out = rows.filter_map(|r| r.ok()).collect();
        }
    }
    out
}

/// `ip:port (service)` location label for a finding.
pub fn target_label(ip: Option<&str>, port: Option<i64>, service: Option<&str>) -> String {
    let host = ip.unwrap_or("—").to_string();
    let mut s = match port {
        Some(p) => format!("{host}:{p}"),
        None => host,
    };
    if let Some(svc) = service.filter(|s| !s.is_empty()) {
        s.push_str(&format!(" ({svc})"));
    }
    s
}

// ---------------------------------------------------------------------------
// Finding detail (+ validate-agent verification history)
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct FindingDetail {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub phase: String,
    pub tool: String,
    pub target_ip: Option<String>,
    pub target_port: Option<i64>,
    pub service: Option<String>,
    pub cvss_score: Option<f64>,
    pub cve_ids: Option<String>,
    pub remediation: Option<String>,
    pub evidence_path: Option<String>,
    pub verified: bool,
    pub false_positive: bool,
    pub created_at: String,
    pub verifications: Vec<Verification>,
}

/// One validate-agent adjudication row (`finding_verifications`).
pub struct Verification {
    pub verdict: String,
    pub verifier: String,
    pub rationale: String,
    pub created_at: String,
}

pub fn finding_detail(conn: &Connection, eng: &str, id: &str) -> Result<Option<FindingDetail>> {
    let row = conn.query_row(
        "SELECT id, severity, title, description, phase, tool, target_ip, target_port, service,
                cvss_score, cve_ids, remediation, evidence_path, verified, false_positive, created_at
         FROM findings WHERE engagement_id = ?1 AND id = ?2",
        rusqlite::params![eng, id],
        |r| {
            Ok(FindingDetail {
                id: r.get(0)?,
                severity: r.get(1)?,
                title: r.get(2)?,
                description: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                phase: r.get(4)?,
                tool: r.get(5)?,
                target_ip: r.get(6)?,
                target_port: r.get(7)?,
                service: r.get(8)?,
                cvss_score: r.get(9)?,
                cve_ids: r.get(10)?,
                remediation: r.get(11)?,
                evidence_path: r.get(12)?,
                verified: r.get(13)?,
                false_positive: r.get(14)?,
                created_at: r.get(15)?,
                verifications: Vec::new(),
            })
        },
    );
    let mut d = match row {
        Ok(d) => d,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if let Ok(mut stmt) = conn.prepare(
        "SELECT verdict, verifier, rationale, created_at FROM finding_verifications \
         WHERE finding_id = ?1 ORDER BY created_at",
    ) {
        if let Ok(rows) = stmt.query_map([id], |r| {
            Ok(Verification {
                verdict: r.get(0)?,
                verifier: r.get(1)?,
                rationale: r.get(2)?,
                created_at: r.get(3)?,
            })
        }) {
            d.verifications = rows.filter_map(|r| r.ok()).collect();
        }
    }
    Ok(Some(d))
}

// ---------------------------------------------------------------------------
// Knowledge triples
// ---------------------------------------------------------------------------

/// (subject, predicate, object, confidence, source_tool, phase).
pub type TripleRow = (String, String, String, f64, Option<String>, String);

pub fn knowledge(conn: &Connection, eng: &str) -> Result<Vec<TripleRow>> {
    let mut stmt = conn.prepare(
        "SELECT subject, predicate, object, confidence, source_tool, phase
         FROM knowledge WHERE engagement_id = ?1 ORDER BY confidence DESC, subject",
    )?;
    let rows = stmt
        .query_map([eng], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, f64>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Evidence = tool_runs (the Cedar-gated execution log)
// ---------------------------------------------------------------------------

pub struct ToolRunRow {
    pub tool: String,
    pub command: String,
    pub exit_code: Option<i64>,
    pub duration_ms: Option<i64>,
    pub cedar_decision: Option<String>,
    pub cedar_policy: Option<String>,
    pub approved_by: Option<String>,
    pub output_file: Option<String>,
    pub created_at: String,
}

pub fn tool_runs(conn: &Connection, eng: &str) -> Result<Vec<ToolRunRow>> {
    let mut stmt = conn.prepare(
        "SELECT tool, command, exit_code, duration_ms, cedar_decision, cedar_policy,
                approved_by, output_file, created_at
         FROM tool_runs WHERE engagement_id = ?1 ORDER BY created_at DESC",
    )?;
    let rows = stmt
        .query_map([eng], |r| {
            Ok(ToolRunRow {
                tool: r.get(0)?,
                command: r.get(1)?,
                exit_code: r.get(2)?,
                duration_ms: r.get(3)?,
                cedar_decision: r.get(4)?,
                cedar_policy: r.get(5)?,
                approved_by: r.get(6)?,
                output_file: r.get(7)?,
                created_at: r.get(8)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Graph: hosts (compound) → findings, overlaid with knowledge subject→object
// edges. Concepts named in knowledge that aren't a finding id become their own
// light "concept" nodes. graph.js does layout / clustering / coloring.
// ---------------------------------------------------------------------------

pub fn graph(conn: &Connection, eng: &str) -> Result<serde_json::Value> {
    use serde_json::json;

    // Finding nodes (carry every dimension the client can cluster/color by).
    let mut fstmt = conn.prepare(
        "SELECT id, severity, phase, tool, COALESCE(target_ip,'(no host)'),
                target_port, COALESCE(service,''), title, verified, false_positive
         FROM findings WHERE engagement_id = ?1",
    )?;
    let mut nodes: Vec<serde_json::Value> = Vec::new();
    let mut finding_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let frows = fstmt.query_map([eng], |r| {
        let id: String = r.get(0)?;
        let port: Option<i64> = r.get(5)?;
        let verified: bool = r.get(8)?;
        let false_positive: bool = r.get(9)?;
        let status = if verified {
            "verified"
        } else if false_positive {
            "false_positive"
        } else {
            "pending"
        };
        Ok(json!({
            "id":       id,
            "kind":     "finding",
            "severity": r.get::<_, String>(1)?,
            "phase":    r.get::<_, String>(2)?,
            "tool":     r.get::<_, String>(3)?,
            "host":     r.get::<_, String>(4)?,
            "port":     port,
            "service":  r.get::<_, String>(6)?,
            "title":    r.get::<_, String>(7)?,
            "status":   status,
        }))
    })?;
    for row in frows.filter_map(|r| r.ok()) {
        if let Some(id) = row.get("id").and_then(|v| v.as_str()) {
            finding_ids.insert(id.to_string());
        }
        nodes.push(row);
    }

    // Knowledge edges: subject --predicate--> object. A subject/object that is a
    // finding id links straight to that node; otherwise it becomes a "concept"
    // node (deduped). source_finding_id, when set, links the originating finding
    // to the subject.
    let mut concepts: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut edges: Vec<serde_json::Value> = Vec::new();
    let mut seen_edges: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();

    let ensure_concept =
        |val: &str, nodes: &mut Vec<serde_json::Value>, concepts: &mut std::collections::HashSet<String>| -> String {
            if finding_ids.contains(val) {
                return val.to_string();
            }
            let nid = format!("concept:{val}");
            if concepts.insert(nid.clone()) {
                nodes.push(json!({ "id": nid, "kind": "concept", "label": val }));
            }
            nid
        };

    let mut kstmt = conn.prepare(
        "SELECT subject, predicate, object, COALESCE(source_finding_id,'')
         FROM knowledge WHERE engagement_id = ?1",
    )?;
    let krows = kstmt.query_map([eng], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })?;
    for (subject, predicate, object, src) in krows.filter_map(|r| r.ok()) {
        let s = ensure_concept(&subject, &mut nodes, &mut concepts);
        let o = ensure_concept(&object, &mut nodes, &mut concepts);
        if s != o && seen_edges.insert((s.clone(), o.clone())) {
            edges.push(json!({ "source": s, "target": o, "label": predicate, "kind": "knowledge" }));
        }
        if !src.is_empty() && finding_ids.contains(&src) {
            let key = (src.clone(), s.clone());
            if src != s && seen_edges.insert(key) {
                edges.push(json!({ "source": src, "target": s, "label": "derived", "kind": "derived" }));
            }
        }
    }

    Ok(json!({ "nodes": nodes, "edges": edges }))
}

// Audit-journal linkage/sealing lives in the shared `crate::audit` module so the
// `redteam-seal` binary and the viewer agree on one implementation.
pub use crate::audit::{verify_chain_linkage, Linkage};

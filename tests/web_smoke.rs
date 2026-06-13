//! Smoke test for the read-only web viewer: seed a tiny engagement DB, then
//! drive every route through the router and assert it renders (200) with the
//! expected content. Mirrors the codered viewer's smoke test.

use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use rusqlite::Connection;
use symbi_redteam::web::{build_router, AppState};
use tower::ServiceExt; // for `oneshot`

const SCHEMA: &str = include_str!("../db/schema.sql");

fn seed_db(path: &std::path::Path) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(SCHEMA).unwrap();
    conn.execute(
        "INSERT INTO engagements (id, client, scope_hash, start_date, end_date, status)
         VALUES ('eng-1', 'Acme Lab', 'abc', '2026-01-01', '2026-01-02', 'active')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO findings (id, engagement_id, phase, tool, target_ip, target_port, service,
                               severity, title, description, cvss_score, verified, false_positive)
         VALUES ('f-1', 'eng-1', 'vuln', 'nuclei', '10.0.2.15', 445, 'smb',
                 'high', 'SMB null session', 'Anonymous SMB access', 8.1, 1, 0)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO findings (id, engagement_id, phase, tool, target_ip, severity, title, false_positive)
         VALUES ('f-2', 'eng-1', 'recon', 'nmap', '10.0.2.16', 'info', 'Open port 80', 1)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO finding_verifications (id, finding_id, verdict, rationale, verifier)
         VALUES ('v-1', 'f-1', 'verified', 'Reproduced anonymous mount', 'validate')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tool_runs (id, engagement_id, tool, command, exit_code, cedar_decision, cedar_policy)
         VALUES ('t-1', 'eng-1', 'nmap', 'nmap -sV 10.0.2.15', 0, 'Allow', 'tool-authorization')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO knowledge (id, engagement_id, phase, subject, predicate, object, confidence, source_finding_id)
         VALUES ('k-1', 'eng-1', 'enum', 'smb_null_session', 'enabled_on', '10.0.2.15:445', 0.9, 'f-1')",
        [],
    )
    .unwrap();
}

fn state() -> (tempfile::TempDir, AppState) {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("redteam.db");
    seed_db(&db);
    let state = AppState {
        db_path: db,
        engagement_id: "eng-1".to_string(),
        journal_path: None,
        report_path: None,
    };
    (dir, state)
}

async fn get(state: &AppState, uri: &str) -> (StatusCode, String) {
    let resp = build_router(state.clone())
        .oneshot(Request::builder().uri(uri).body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 4 * 1024 * 1024).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
async fn pages_render() {
    let (_dir, st) = state();

    for (uri, needle) in [
        ("/", "Acme Lab"),
        ("/findings", "SMB null session"),
        ("/findings/f-1", "Reproduced anonymous mount"), // validate-agent trail
        ("/knowledge", "smb_null_session"),
        ("/evidence", "nmap -sV 10.0.2.15"),
        ("/graph", "Engagement graph"),
        ("/report", "No report.md"),
        ("/help", "glossary"),
        ("/healthz", "ok"),
    ] {
        let (status, body) = get(&st, uri).await;
        assert_eq!(status, StatusCode::OK, "GET {uri} -> {status}");
        assert!(body.contains(needle), "GET {uri} missing {needle:?}");
    }
}

#[tokio::test]
async fn finding_filter_and_status() {
    let (_dir, st) = state();

    // Severity filter narrows the table.
    let (_, body) = get(&st, "/findings?severity=high").await;
    assert!(body.contains("SMB null session"));
    assert!(!body.contains("Open port 80"));

    // Verified finding shows the validate status; false-positive shows its own.
    let (_, detail) = get(&st, "/findings/f-1").await;
    assert!(detail.contains("✓ verified"));
    let (_, fp) = get(&st, "/findings/f-2").await;
    assert!(fp.contains("✕ false positive"));
}

#[tokio::test]
async fn graph_api_has_finding_and_concept_nodes() {
    let (_dir, st) = state();
    let (status, body) = get(&st, "/api/graph").await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let nodes = v["nodes"].as_array().unwrap();
    assert!(nodes.iter().any(|n| n["kind"] == "finding"));
    // The knowledge triple's object becomes a concept node, subject links to f-1.
    assert!(nodes.iter().any(|n| n["kind"] == "concept"));
    let edges = v["edges"].as_array().unwrap();
    assert!(!edges.is_empty());
}

#[tokio::test]
async fn unknown_finding_is_404() {
    let (_dir, st) = state();
    let (status, _) = get(&st, "/findings/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

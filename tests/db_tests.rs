use symbi_redteam::db;

/// Helper: create an in-memory database with schema applied.
fn test_db() -> rusqlite::Connection {
    db::init_db(":memory:").expect("Failed to init in-memory DB")
}

/// Helper: create a test engagement and return its ID.
fn create_test_engagement(conn: &rusqlite::Connection) -> String {
    db::create_engagement(
        conn,
        "TestCorp",
        "[engagement]\nid = \"test\"",
        "2026-04-01",
        "2026-04-30",
    )
    .expect("Failed to create engagement")
}

// =============================================================================
// Schema initialization
// =============================================================================

#[test]
fn init_db_creates_tables() {
    let conn = test_db();
    // Verify core tables exist by querying sqlite_master
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    assert!(tables.contains(&"engagements".to_string()));
    assert!(tables.contains(&"findings".to_string()));
    assert!(tables.contains(&"tool_runs".to_string()));
}

#[test]
fn init_db_is_idempotent() {
    let conn = test_db();
    // Re-running init should not fail (CREATE IF NOT EXISTS)
    conn.execute_batch(include_str!("../db/schema.sql")).unwrap();
}

// =============================================================================
// Engagement CRUD
// =============================================================================

#[test]
fn create_engagement_returns_uuid() {
    let conn = test_db();
    let id = create_test_engagement(&conn);
    assert!(!id.is_empty());
    // Should look like a UUID (36 chars with hyphens)
    assert_eq!(id.len(), 36);
    assert_eq!(id.chars().filter(|c| *c == '-').count(), 4);
}

#[test]
fn get_engagement_returns_created() {
    let conn = test_db();
    let id = create_test_engagement(&conn);
    let eng = db::get_engagement(&conn, &id).unwrap().unwrap();
    assert_eq!(eng.client, "TestCorp");
    assert_eq!(eng.status, "planning");
    assert_eq!(eng.start_date, "2026-04-01");
}

#[test]
fn get_engagement_returns_none_for_missing() {
    let conn = test_db();
    let result = db::get_engagement(&conn, "nonexistent-id").unwrap();
    assert!(result.is_none());
}

#[test]
fn update_engagement_status_works() {
    let conn = test_db();
    let id = create_test_engagement(&conn);
    let rows = db::update_engagement_status(&conn, &id, "active").unwrap();
    assert_eq!(rows, 1);
    let eng = db::get_engagement(&conn, &id).unwrap().unwrap();
    assert_eq!(eng.status, "active");
}

// =============================================================================
// Finding CRUD
// =============================================================================

fn test_finding(engagement_id: &str) -> db::NewFinding {
    db::NewFinding {
        engagement_id: engagement_id.to_string(),
        phase: "recon".to_string(),
        tool: "nmap_scan".to_string(),
        target_ip: Some("10.0.1.5".to_string()),
        target_port: Some(22),
        service: Some("ssh".to_string()),
        severity: "high".to_string(),
        title: "SSH exposed on staging".to_string(),
        description: Some("OpenSSH 7.4 on port 22".to_string()),
        evidence_path: None,
        cvss_score: Some(7.5),
        cve_ids: None,
        remediation: Some("Restrict SSH to bastion host".to_string()),
        verified: false,
        false_positive: false,
    }
}

#[test]
fn insert_finding_returns_id() {
    let conn = test_db();
    let eng_id = create_test_engagement(&conn);
    let finding = test_finding(&eng_id);
    let finding_id = db::insert_finding(&conn, &finding).unwrap();
    assert!(!finding_id.is_empty());
}

#[test]
fn query_findings_returns_inserted() {
    let conn = test_db();
    let eng_id = create_test_engagement(&conn);

    let f1 = test_finding(&eng_id);
    db::insert_finding(&conn, &f1).unwrap();

    let mut f2 = test_finding(&eng_id);
    f2.severity = "critical".to_string();
    f2.title = "RCE via CVE-2024-1234".to_string();
    db::insert_finding(&conn, &f2).unwrap();

    let results = db::query_findings(&conn, &eng_id, None, None, None).unwrap();
    assert_eq!(results.len(), 2);
}

#[test]
fn query_findings_filters_by_severity() {
    let conn = test_db();
    let eng_id = create_test_engagement(&conn);

    let f1 = test_finding(&eng_id);
    db::insert_finding(&conn, &f1).unwrap();

    let mut f2 = test_finding(&eng_id);
    f2.severity = "low".to_string();
    db::insert_finding(&conn, &f2).unwrap();

    let results = db::query_findings(&conn, &eng_id, None, Some("high"), None).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].severity, "high");
}

// =============================================================================
// Engagement summary
// =============================================================================

#[test]
fn engagement_summary_counts_severities() {
    let conn = test_db();
    let eng_id = create_test_engagement(&conn);

    // Insert findings with different severities
    for (sev, count) in [("critical", 1), ("high", 2), ("medium", 3)] {
        for _ in 0..count {
            let mut f = test_finding(&eng_id);
            f.severity = sev.to_string();
            db::insert_finding(&conn, &f).unwrap();
        }
    }

    let summary = db::get_engagement_summary(&conn, &eng_id).unwrap();
    assert_eq!(summary.total_findings, 6);
    assert_eq!(summary.critical_count, 1);
    assert_eq!(summary.high_count, 2);
    assert_eq!(summary.medium_count, 3);
    assert_eq!(summary.low_count, 0);
    assert_eq!(summary.info_count, 0);
}

// =============================================================================
// Tool runs
// =============================================================================

#[test]
fn store_and_query_tool_runs() {
    let conn = test_db();
    let eng_id = create_test_engagement(&conn);

    let tool_run = db::NewToolRun {
        engagement_id: eng_id.clone(),
        finding_id: None,
        tool: "nmap_scan".to_string(),
        command: "nmap -sV 10.0.1.0/24".to_string(),
        arguments: Some("-sV".to_string()),
        exit_code: Some(0),
        duration_ms: Some(1234),
        output_file: Some("/app/.symbiont/scans/test.xml".to_string()),
        cedar_decision: Some("allowed".to_string()),
        cedar_policy: Some("tool-authorization".to_string()),
        approved_by: None,
    };
    db::insert_tool_run(&conn, &tool_run).unwrap();

    let runs = db::get_tool_runs(&conn, &eng_id, None).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].tool, "nmap_scan");
    assert_eq!(runs[0].cedar_decision, Some("allowed".to_string()));
}

// =============================================================================
// Audit hash integrity
// =============================================================================

#[test]
fn finding_has_audit_hash() {
    let conn = test_db();
    let eng_id = create_test_engagement(&conn);
    let finding = test_finding(&eng_id);
    db::insert_finding(&conn, &finding).unwrap();

    let results = db::query_findings(&conn, &eng_id, None, None, None).unwrap();
    assert!(results[0].audit_hash.is_some());
    let hash = results[0].audit_hash.as_ref().unwrap();
    // SHA-256 hex is 64 chars
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

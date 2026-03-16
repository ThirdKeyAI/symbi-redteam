-- =============================================================================
-- schema.sql -- SQLite schema for the pen test evidence database
-- =============================================================================

CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    client TEXT NOT NULL,
    scope_hash TEXT NOT NULL,
    start_date DATETIME NOT NULL,
    end_date DATETIME NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('planning','active','paused','complete')),
    roa_hash TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    phase TEXT NOT NULL CHECK(phase IN ('recon','enum','vuln','exploit','post_exploit')),
    tool TEXT NOT NULL,
    target_ip TEXT,
    target_port INTEGER,
    service TEXT,
    severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','info')),
    title TEXT NOT NULL,
    description TEXT,
    evidence_path TEXT,
    cvss_score REAL,
    cve_ids TEXT,
    remediation TEXT,
    verified BOOLEAN DEFAULT FALSE,
    false_positive BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    audit_hash TEXT
);

CREATE TABLE IF NOT EXISTS tool_runs (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    finding_id TEXT REFERENCES findings(id),
    tool TEXT NOT NULL,
    command TEXT NOT NULL,
    arguments TEXT,
    exit_code INTEGER,
    duration_ms INTEGER,
    output_file TEXT,
    cedar_decision TEXT,
    cedar_policy TEXT,
    approved_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS retests (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    baseline_engagement_id TEXT NOT NULL REFERENCES engagements(id),
    finding_id TEXT NOT NULL REFERENCES findings(id),
    baseline_finding_id TEXT NOT NULL REFERENCES findings(id),
    status TEXT NOT NULL CHECK(status IN ('remediated','persistent','regressed','new')),
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_phase ON findings(phase);
CREATE INDEX IF NOT EXISTS idx_tool_runs_engagement ON tool_runs(engagement_id);
CREATE INDEX IF NOT EXISTS idx_tool_runs_tool ON tool_runs(tool);
CREATE INDEX IF NOT EXISTS idx_retests_engagement ON retests(engagement_id);

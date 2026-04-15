use crate::approvals::types::{ApprovalDecision, ApprovalRequest};
use chrono::Utc;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent<'a> {
    ApprovalRequested {
        request: &'a ApprovalRequest,
        channels: Vec<&'static str>,
    },
    ApprovalDecided {
        decision: &'a ApprovalDecision,
        latency_ms: u64,
    },
    SlackUnauthorizedClick {
        request_id: uuid::Uuid,
        slack_user_id: String,
    },
}

pub struct ApprovalAuditLogger {
    path: PathBuf,
    inner: Arc<Mutex<()>>, // serialize writes
}

impl ApprovalAuditLogger {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), inner: Arc::new(Mutex::new(())) }
    }

    pub async fn log<'a>(&self, event: AuditEvent<'a>) -> std::io::Result<()> {
        let line = serde_json::to_string(&serde_json::json!({
            "ts": Utc::now().to_rfc3339(),
            "kind": "approval",
            "payload": event,
        }))?;
        let _g = self.inner.lock().await;
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut f = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
        f.write_all(line.as_bytes()).await?;
        f.write_all(b"\n").await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approvals::types::{Approver, Outcome, RiskTier};
    use uuid::Uuid;

    fn req() -> ApprovalRequest {
        ApprovalRequest {
            request_id: Uuid::nil(),
            engagement_id: "eng-1".into(),
            agent_name: "exploit".into(),
            tool: "metasploit_run".into(),
            args_redacted: serde_json::json!({"module": "exploit/multi/handler"}),
            target: "10.0.1.5".into(),
            risk_tier: RiskTier::High,
            requested_at: Utc::now(),
            expires_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn writes_jsonl_line_per_event() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approvals.jsonl");
        let log = ApprovalAuditLogger::new(&path);

        log.log(AuditEvent::ApprovalRequested { request: &req(), channels: vec!["cli", "slack"] })
            .await
            .unwrap();
        log.log(AuditEvent::ApprovalDecided {
            decision: &ApprovalDecision {
                request_id: Uuid::nil(),
                outcome: Outcome::Approve,
                approver: Approver::Cli { user: "operator".into() },
                reason: None,
                decided_at: Utc::now(),
            },
            latency_ms: 1234,
        })
        .await
        .unwrap();

        let body = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["payload"]["event"], "approval_requested");
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["payload"]["event"], "approval_decided");
        assert_eq!(second["payload"]["latency_ms"], 1234);
    }
}

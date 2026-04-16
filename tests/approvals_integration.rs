use chrono::Utc;
use serde_json::json;
use std::sync::Arc;
use symbi_redteam::approvals::audit::ApprovalAuditLogger;
use symbi_redteam::approvals::cli::{CliPrompter, Tty};
use symbi_redteam::approvals::config::ResolvedSlackConfig;
use symbi_redteam::approvals::dispatcher::DualChannelDispatcher;
use symbi_redteam::approvals::slack_relay::SlackApprovalRelay;
use symbi_redteam::approvals::types::*;
use tokio::sync::oneshot;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct BlockingTty;
#[async_trait::async_trait]
impl Tty for BlockingTty {
    async fn write_prompt(&self, _: &str) -> std::io::Result<()> { Ok(()) }
    async fn read_line(&self) -> std::io::Result<Option<String>> {
        std::future::pending::<()>().await;
        unreachable!()
    }
    async fn write_line(&self, _: &str) -> std::io::Result<()> { Ok(()) }
}

fn cfg(_uri: String) -> ResolvedSlackConfig {
    ResolvedSlackConfig {
        bot_token: "xoxb-test".into(),
        signing_secret: "ssss".into(),
        channel: "C1".into(),
        approvers: vec!["U1".into()],
        dm_approvers: false,
        events_bind_addr: "127.0.0.1:0".into(),
    }
}

fn ctx() -> String {
    serde_json::to_string(&json!({
        "engagement_id": "eng-1",
        "agent_name": "exploit",
        "tool": "metasploit_run",
        "target": "10.0.1.5",
        "risk_tier": "high",
        "args_redacted": {"m": "x"}
    })).unwrap()
}

#[tokio::test]
async fn slack_approval_wins_over_blocking_cli() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true, "ts": "1.2"})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat.update"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true, "ts": "1.2"})))
        .mount(&server)
        .await;

    let relay = Arc::new(SlackApprovalRelay::new(cfg(server.uri())).with_base_url(server.uri()));
    let dir = tempfile::tempdir().unwrap();
    let dispatcher = Arc::new(DualChannelDispatcher {
        cli: Arc::new(CliPrompter { tty: Arc::new(BlockingTty), user_label: "op".into() }),
        slack: Some(relay.clone()),
        audit: Arc::new(ApprovalAuditLogger::new(dir.path().join("a.jsonl"))),
    });

    let (tx, rx) = oneshot::channel();
    let req_id = Uuid::from_u128(42);
    let dispatcher_clone = dispatcher.clone();
    let handle = tokio::spawn(async move {
        dispatcher_clone.handle_one(
            req_id.to_string(),
            ctx(),
            Utc::now() + chrono::Duration::seconds(10),
            tx,
        ).await;
    });

    // Give the dispatcher a moment to register the pending state
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Simulate Slack click
    let decision = ApprovalDecision {
        request_id: req_id,
        outcome: Outcome::Approve,
        approver: Approver::Slack { user_id: "U1".into(), message_ts: "1.2".into() },
        reason: None,
        decided_at: Utc::now(),
    };
    assert!(relay.try_resolve(req_id, decision));

    let approved = rx.await.unwrap();
    assert!(approved);
    handle.await.unwrap();
}

use crate::approvals::audit::{ApprovalAuditLogger, AuditEvent};
use crate::approvals::cli::{CliPrompter, Tty};
use crate::approvals::slack_relay::SlackApprovalRelay;
use crate::approvals::types::{ApprovalDecision, ApprovalRequest, Approver, Outcome, RiskTier};
use chrono::Utc;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct ReviewContextJson {
    engagement_id: String,
    agent_name: String,
    tool: String,
    target: String,
    risk_tier: RiskTier,
    #[serde(default)]
    args_redacted: serde_json::Value,
}

pub struct DualChannelDispatcher<T: Tty + 'static> {
    pub cli: Arc<CliPrompter<T>>,
    pub slack: Option<Arc<SlackApprovalRelay>>,
    pub audit: Arc<ApprovalAuditLogger>,
}

impl<T: Tty + 'static> DualChannelDispatcher<T> {
    pub async fn handle_one(
        &self,
        review_id: String,
        context_json: String,
        deadline: chrono::DateTime<chrono::Utc>,
        respond: oneshot::Sender<bool>,
    ) {
        let parsed: ReviewContextJson = match serde_json::from_str(&context_json) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "invalid review context, denying");
                let _ = respond.send(false);
                return;
            }
        };
        let request_id = Uuid::parse_str(&review_id).unwrap_or_else(|_| Uuid::new_v4());
        let req = ApprovalRequest {
            request_id,
            engagement_id: parsed.engagement_id,
            agent_name: parsed.agent_name,
            tool: parsed.tool,
            args_redacted: parsed.args_redacted,
            target: parsed.target,
            risk_tier: parsed.risk_tier,
            requested_at: Utc::now(),
            expires_at: deadline,
        };

        let mut channels: Vec<&'static str> = vec!["cli"];
        let cancel = CancellationToken::new();

        // CLI task
        let cli = self.cli.clone();
        let cli_cancel = cancel.clone();
        let cli_req = req.clone();
        let (cli_tx, cli_rx) = oneshot::channel::<ApprovalDecision>();
        tokio::spawn(async move {
            if let Ok(Some(d)) = cli.prompt(&cli_req, cli_cancel).await {
                let _ = cli_tx.send(d);
            }
        });

        // Slack task
        let slack_rx_opt = if let Some(slack) = &self.slack {
            channels.push("slack");
            match slack.request_approval(&req).await {
                Ok(rx) => Some(rx),
                Err(e) => {
                    tracing::warn!(error = %e, "slack request failed; CLI-only");
                    None
                }
            }
        } else {
            None
        };

        let _ = self
            .audit
            .log(AuditEvent::ApprovalRequested {
                request: &req,
                channels,
            })
            .await;

        let started = Instant::now();
        let decision = race(req.clone(), cli_rx, slack_rx_opt, deadline, cancel.clone()).await;

        // Cancel the loser
        cancel.cancel();

        // Update Slack UI (regardless of who won)
        if let Some(slack) = &self.slack {
            if let Some(ts) = slack.take_channel_ts(decision.request_id) {
                if let Err(e) = slack.finalize_resolution(&ts, &decision).await {
                    tracing::warn!(error = %e, "slack finalize update failed");
                }
            }
        }

        let _ = self
            .audit
            .log(AuditEvent::ApprovalDecided {
                decision: &decision,
                latency_ms: started.elapsed().as_millis() as u64,
            })
            .await;

        let _ = respond.send(decision.approved());
    }
}

async fn race(
    req: ApprovalRequest,
    cli_rx: oneshot::Receiver<ApprovalDecision>,
    slack_rx: Option<oneshot::Receiver<ApprovalDecision>>,
    deadline: chrono::DateTime<chrono::Utc>,
    cancel: CancellationToken,
) -> ApprovalDecision {
    let until = deadline
        .signed_duration_since(Utc::now())
        .to_std()
        .unwrap_or(std::time::Duration::from_secs(0));
    let sleep = tokio::time::sleep(until);
    tokio::pin!(sleep);

    match slack_rx {
        Some(slack_rx) => {
            tokio::select! {
                d = cli_rx => { cancel.cancel(); d.unwrap_or_else(|_| expired(&req)) }
                d = slack_rx => { cancel.cancel(); d.unwrap_or_else(|_| expired(&req)) }
                _ = &mut sleep => { cancel.cancel(); expired(&req) }
            }
        }
        None => {
            tokio::select! {
                d = cli_rx => { cancel.cancel(); d.unwrap_or_else(|_| expired(&req)) }
                _ = &mut sleep => { cancel.cancel(); expired(&req) }
            }
        }
    }
}

fn expired(req: &ApprovalRequest) -> ApprovalDecision {
    ApprovalDecision {
        request_id: req.request_id,
        outcome: Outcome::Expired,
        approver: Approver::System,
        reason: Some("deadline reached".into()),
        decided_at: Utc::now(),
    }
}

/// Run loop: bridge a tokio mpsc of (review_id, context, deadline, respond)
/// into per-request handle_one tasks.
pub async fn run<T: Tty + 'static>(
    dispatcher: Arc<DualChannelDispatcher<T>>,
    mut rx: mpsc::Receiver<(String, String, chrono::DateTime<chrono::Utc>, oneshot::Sender<bool>)>,
) {
    while let Some((id, ctx, dl, respond)) = rx.recv().await {
        let d = dispatcher.clone();
        tokio::spawn(async move { d.handle_one(id, ctx, dl, respond).await });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approvals::cli::{CliPrompter, Tty};

    struct ApprovingTty;
    #[async_trait::async_trait]
    impl Tty for ApprovingTty {
        async fn write_prompt(&self, _: &str) -> std::io::Result<()> { Ok(()) }
        async fn read_line(&self) -> std::io::Result<Option<String>> { Ok(Some("y".into())) }
        async fn write_line(&self, _: &str) -> std::io::Result<()> { Ok(()) }
    }

    fn ctx() -> String {
        serde_json::to_string(&serde_json::json!({
            "engagement_id": "eng-1",
            "agent_name": "exploit",
            "tool": "metasploit_run",
            "target": "10.0.1.5",
            "risk_tier": "high",
            "args_redacted": {"module": "x"}
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn cli_approval_with_no_slack() {
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(ApprovalAuditLogger::new(dir.path().join("a.jsonl")));
        let dispatcher = DualChannelDispatcher {
            cli: Arc::new(CliPrompter {
                tty: Arc::new(ApprovingTty),
                user_label: "op".into(),
            }),
            slack: None,
            audit,
        };
        let (tx, rx) = oneshot::channel();
        dispatcher
            .handle_one(
                Uuid::from_u128(1).to_string(),
                ctx(),
                Utc::now() + chrono::Duration::seconds(30),
                tx,
            )
            .await;
        assert!(rx.await.unwrap());
    }

    #[tokio::test]
    async fn expiration_denies_when_no_input() {
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
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(ApprovalAuditLogger::new(dir.path().join("a.jsonl")));
        let dispatcher = DualChannelDispatcher {
            cli: Arc::new(CliPrompter {
                tty: Arc::new(BlockingTty),
                user_label: "op".into(),
            }),
            slack: None,
            audit,
        };
        let (tx, rx) = oneshot::channel();
        dispatcher
            .handle_one(
                Uuid::from_u128(2).to_string(),
                ctx(),
                Utc::now() + chrono::Duration::milliseconds(100),
                tx,
            )
            .await;
        assert!(!rx.await.unwrap());
    }
}

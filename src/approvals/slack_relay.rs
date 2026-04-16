use crate::approvals::blocks;
use crate::approvals::config::ResolvedSlackConfig;
use crate::approvals::types::{ApprovalDecision, ApprovalRequest};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use uuid::Uuid;

#[derive(Debug)]
pub struct PendingState {
    pub tx: oneshot::Sender<ApprovalDecision>,
    pub channel_msg_ts: String,
    pub dm_msg_tss: Vec<(String, String)>, // (user_id, ts)
}

#[derive(Clone)]
pub struct SlackApprovalRelay {
    cfg: ResolvedSlackConfig,
    http: reqwest::Client,
    pending: Arc<DashMap<Uuid, PendingState>>,
    base_url: String, // overrideable for tests
}

#[derive(Debug, thiserror::Error)]
pub enum SlackError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("slack api error: {0}")]
    Api(String),
}

#[derive(Deserialize)]
struct PostMessageResp {
    ok: bool,
    ts: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct PostMessage<'a> {
    channel: &'a str,
    blocks: serde_json::Value,
    text: &'a str, // fallback
}

impl SlackApprovalRelay {
    pub fn new(cfg: ResolvedSlackConfig) -> Self {
        Self {
            cfg,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
            pending: Arc::new(DashMap::new()),
            base_url: "https://slack.com/api".into(),
        }
    }

    /// For tests: point at a wiremock server.
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    async fn post_message(
        &self,
        channel: &str,
        blocks: serde_json::Value,
        text: &str,
    ) -> Result<String, SlackError> {
        let body = PostMessage { channel, blocks, text };
        let resp: PostMessageResp = self
            .http
            .post(format!("{}/chat.postMessage", self.base_url))
            .bearer_auth(&self.cfg.bot_token)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;
        if !resp.ok {
            return Err(SlackError::Api(
                resp.error.unwrap_or_else(|| "unknown".into()),
            ));
        }
        resp.ts
            .ok_or_else(|| SlackError::Api("missing ts".into()))
    }

    async fn update_message(
        &self,
        channel: &str,
        ts: &str,
        blocks: serde_json::Value,
    ) -> Result<(), SlackError> {
        let body = serde_json::json!({
            "channel": channel,
            "ts": ts,
            "blocks": blocks,
            "text": "approval status update",
        });
        let resp: PostMessageResp = self
            .http
            .post(format!("{}/chat.update", self.base_url))
            .bearer_auth(&self.cfg.bot_token)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;
        if !resp.ok {
            return Err(SlackError::Api(
                resp.error.unwrap_or_else(|| "unknown".into()),
            ));
        }
        Ok(())
    }

    pub async fn request_approval(
        &self,
        req: &ApprovalRequest,
    ) -> Result<oneshot::Receiver<ApprovalDecision>, SlackError> {
        let blocks_v = blocks::request_blocks(req);
        let fallback = format!("Approval required: {} on {}", req.tool, req.target);
        let channel_ts = self
            .post_message(&self.cfg.channel, blocks_v, &fallback)
            .await?;

        let mut dm_msg_tss = Vec::new();
        if self.cfg.dm_approvers {
            let dm_blocks = blocks::dm_blocks(req, "https://slack.com");
            for user in &self.cfg.approvers {
                match self
                    .post_message(user, dm_blocks.clone(), &fallback)
                    .await
                {
                    Ok(ts) => dm_msg_tss.push((user.clone(), ts)),
                    Err(e) => tracing::warn!(
                        approver = %user,
                        error = %e,
                        "DM failed, continuing"
                    ),
                }
            }
        }

        let (tx, rx) = oneshot::channel();
        self.pending.insert(
            req.request_id,
            PendingState {
                tx,
                channel_msg_ts: channel_ts,
                dm_msg_tss,
            },
        );
        Ok(rx)
    }

    /// Called by the HTTP handler when an approver clicks a button.
    /// Sends the decision through the oneshot if still pending.
    pub fn try_resolve(&self, request_id: Uuid, decision: ApprovalDecision) -> bool {
        if let Some((_, state)) = self.pending.remove(&request_id) {
            // attempt send; if receiver dropped (race with timeout), we just lose
            let _ = state.tx.send(decision);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approvals::types::RiskTier;
    use chrono::Utc;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cfg(_server_url: String) -> ResolvedSlackConfig {
        ResolvedSlackConfig {
            bot_token: "xoxb-test".into(),
            signing_secret: "ssss".into(),
            channel: "C1".into(),
            approvers: vec!["U1".into(), "U2".into()],
            dm_approvers: true,
            events_bind_addr: "0.0.0.0:9082".into(),
        }
    }

    fn req() -> ApprovalRequest {
        ApprovalRequest {
            request_id: Uuid::from_u128(7),
            engagement_id: "eng-1".into(),
            agent_name: "exploit".into(),
            tool: "metasploit_run".into(),
            args_redacted: serde_json::json!({"m":"x"}),
            target: "10.0.1.5".into(),
            risk_tier: RiskTier::High,
            requested_at: Utc::now(),
            expires_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn posts_to_channel_and_dms() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat.postMessage"))
            .and(header("authorization", "Bearer xoxb-test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "ts": "1700000000.000100"
            })))
            .mount(&server)
            .await;

        let relay =
            SlackApprovalRelay::new(cfg(server.uri())).with_base_url(server.uri());
        let _rx = relay.request_approval(&req()).await.unwrap();
        assert_eq!(relay.pending_count(), 1);
    }

    #[tokio::test]
    async fn try_resolve_sends_decision() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat.postMessage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "ts": "1700000000.000100"
            })))
            .mount(&server)
            .await;

        let relay =
            SlackApprovalRelay::new(cfg(server.uri())).with_base_url(server.uri());
        let rx = relay.request_approval(&req()).await.unwrap();
        let decision = ApprovalDecision {
            request_id: Uuid::from_u128(7),
            outcome: crate::approvals::types::Outcome::Approve,
            approver: crate::approvals::types::Approver::Slack {
                user_id: "U1".into(),
                message_ts: "1700000000.000100".into(),
            },
            reason: None,
            decided_at: Utc::now(),
        };
        assert!(relay.try_resolve(Uuid::from_u128(7), decision));
        let got = rx.await.unwrap();
        assert!(got.approved());
    }

    #[tokio::test]
    async fn try_resolve_unknown_request_returns_false() {
        let server = MockServer::start().await;
        let relay =
            SlackApprovalRelay::new(cfg(server.uri())).with_base_url(server.uri());
        let decision = ApprovalDecision {
            request_id: Uuid::from_u128(99),
            outcome: crate::approvals::types::Outcome::Approve,
            approver: crate::approvals::types::Approver::System,
            reason: None,
            decided_at: Utc::now(),
        };
        assert!(!relay.try_resolve(Uuid::from_u128(99), decision));
    }
}

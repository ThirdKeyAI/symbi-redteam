use crate::approvals::types::{ApprovalDecision, ApprovalRequest, Approver, Outcome};
use chrono::Utc;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

/// Trait to abstract terminal IO so tests can drive it deterministically.
#[async_trait::async_trait]
pub trait Tty: Send + Sync {
    async fn write_prompt(&self, msg: &str) -> std::io::Result<()>;
    async fn read_line(&self) -> std::io::Result<Option<String>>;
    async fn write_line(&self, msg: &str) -> std::io::Result<()>;
}

pub struct StdinStdoutTty;

#[async_trait::async_trait]
impl Tty for StdinStdoutTty {
    async fn write_prompt(&self, msg: &str) -> std::io::Result<()> {
        let mut out = tokio::io::stdout();
        out.write_all(msg.as_bytes()).await?;
        out.flush().await
    }
    async fn read_line(&self) -> std::io::Result<Option<String>> {
        let stdin = tokio::io::stdin();
        let mut reader = tokio::io::BufReader::new(stdin);
        let mut buf = String::new();
        let n = reader.read_line(&mut buf).await?;
        if n == 0 { Ok(None) } else { Ok(Some(buf.trim().to_string())) }
    }
    async fn write_line(&self, msg: &str) -> std::io::Result<()> {
        let mut out = tokio::io::stdout();
        out.write_all(msg.as_bytes()).await?;
        out.write_all(b"\n").await?;
        out.flush().await
    }
}

pub struct CliPrompter<T: Tty> {
    pub tty: Arc<T>,
    pub user_label: String,
}

impl<T: Tty + 'static> CliPrompter<T> {
    /// Run the prompt for one request. Returns `Some(decision)` on user
    /// input, `None` if the cancellation token fires first.
    pub async fn prompt(
        &self,
        req: &ApprovalRequest,
        cancel: CancellationToken,
    ) -> std::io::Result<Option<ApprovalDecision>> {
        let header = format!(
            "\n[approval] {} on {} (tool={}, risk={:?}) — approve? [y/N/d=deny+reason]: ",
            req.agent_name, req.target, req.tool, req.risk_tier
        );
        self.tty.write_prompt(&header).await?;

        tokio::select! {
            _ = cancel.cancelled() => {
                self.tty.write_line("\n[approval] resolved via other channel; CLI cancelled.").await.ok();
                Ok(None)
            }
            line = self.tty.read_line() => {
                let line = line?.unwrap_or_default();
                let outcome = match line.trim().to_ascii_lowercase().as_str() {
                    "y" | "yes" | "approve" => Outcome::Approve,
                    "d" | "deny" | "n" | "no" | "" => Outcome::Deny,
                    _ => Outcome::Deny,
                };
                Ok(Some(ApprovalDecision {
                    request_id: req.request_id,
                    outcome,
                    approver: Approver::Cli { user: self.user_label.clone() },
                    reason: None,
                    decided_at: Utc::now(),
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approvals::types::RiskTier;
    use std::sync::Mutex;
    use uuid::Uuid;

    struct FakeTty {
        input: Mutex<Option<String>>,
        output: Mutex<Vec<String>>,
        block: tokio::sync::Notify,
    }

    impl FakeTty {
        fn with_input(s: &str) -> Arc<Self> {
            Arc::new(Self {
                input: Mutex::new(Some(s.to_string())),
                output: Mutex::new(vec![]),
                block: tokio::sync::Notify::new(),
            })
        }
        fn blocking() -> Arc<Self> {
            Arc::new(Self {
                input: Mutex::new(None),
                output: Mutex::new(vec![]),
                block: tokio::sync::Notify::new(),
            })
        }
    }

    #[async_trait::async_trait]
    impl Tty for FakeTty {
        async fn write_prompt(&self, msg: &str) -> std::io::Result<()> {
            self.output.lock().unwrap().push(msg.to_string());
            Ok(())
        }
        async fn read_line(&self) -> std::io::Result<Option<String>> {
            if let Some(s) = self.input.lock().unwrap().take() {
                return Ok(Some(s));
            }
            self.block.notified().await;
            Ok(None)
        }
        async fn write_line(&self, msg: &str) -> std::io::Result<()> {
            self.output.lock().unwrap().push(msg.to_string());
            Ok(())
        }
    }

    fn req() -> ApprovalRequest {
        ApprovalRequest {
            request_id: Uuid::nil(),
            engagement_id: "e".into(),
            agent_name: "exploit".into(),
            tool: "metasploit_run".into(),
            args_redacted: serde_json::json!({}),
            target: "10.0.1.5".into(),
            risk_tier: RiskTier::High,
            requested_at: Utc::now(),
            expires_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn approves_on_y() {
        let tty = FakeTty::with_input("y");
        let p = CliPrompter { tty: tty.clone(), user_label: "op".into() };
        let cancel = CancellationToken::new();
        let d = p.prompt(&req(), cancel).await.unwrap().unwrap();
        assert!(d.approved());
    }

    #[tokio::test]
    async fn denies_on_empty() {
        let tty = FakeTty::with_input("");
        let p = CliPrompter { tty: tty.clone(), user_label: "op".into() };
        let cancel = CancellationToken::new();
        let d = p.prompt(&req(), cancel).await.unwrap().unwrap();
        assert!(!d.approved());
    }

    #[tokio::test]
    async fn cancellation_returns_none() {
        let tty = FakeTty::blocking();
        let p = Arc::new(CliPrompter { tty: tty.clone(), user_label: "op".into() });
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let p_clone = p.clone();
        let h = tokio::spawn(async move { p_clone.prompt(&req(), cancel_clone).await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        cancel.cancel();
        let result = h.await.unwrap().unwrap();
        assert!(result.is_none());
    }
}

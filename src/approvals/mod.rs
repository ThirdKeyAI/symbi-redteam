//! Human-approval dispatcher and transports.
//!
//! Symbiont's `HumanCritic` produces a stream of (ReviewRequest, oneshot::Sender)
//! pairs. The `DualChannelDispatcher` here consumes that stream and fans each
//! request to a CLI prompt and (optionally) a Slack relay, returning the first
//! decision via the oneshot.

pub mod audit;
pub mod blocks;
pub mod cli;
pub mod config;
pub mod dispatcher;
pub mod http;
pub mod slack_relay;
pub mod symbi_bridge;
pub mod types;

pub use config::SlackApprovalConfig;
pub use dispatcher::DualChannelDispatcher;
pub use types::{ApprovalDecision, ApprovalRequest, Approver, Outcome, RiskTier};

pub async fn install(
    symbi_toml_path: &std::path::Path,
    symbi_rx: tokio::sync::mpsc::Receiver<(
        symbi_runtime::reasoning::human_critic::ReviewRequest,
        tokio::sync::oneshot::Sender<symbi_runtime::reasoning::human_critic::ReviewResponse>,
    )>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::approvals::audit::ApprovalAuditLogger;
    use crate::approvals::cli::{CliPrompter, StdinStdoutTty};
    use crate::approvals::config::load_from_symbi_toml;
    use std::sync::Arc;

    let approvals_config = load_from_symbi_toml(symbi_toml_path)?;
    let slack_config = match approvals_config.slack {
        Some(c) if c.enabled => Some(c),
        _ => {
            tracing::info!("slack approvals not enabled, using CLI-only");
            None
        }
    };

    let audit = Arc::new(ApprovalAuditLogger::new("audit-logs/approvals.jsonl"));
    let cli = Arc::new(CliPrompter {
        tty: Arc::new(StdinStdoutTty),
        user_label: "operator".into(),
    });

    let slack = match slack_config {
        Some(ref cfg) => {
            use crate::approvals::slack_relay::SlackApprovalRelay;

            let resolved = cfg.resolve()?;
            let bind_addr = resolved.events_bind_addr.clone();
            let allowlist = resolved.approvers.clone();
            let signing_secret = resolved.signing_secret.clone();
            let relay = Arc::new(SlackApprovalRelay::new(resolved));
            let state = http::AppState {
                relay: relay.clone(),
                signing_secret: Arc::new(signing_secret),
                allowlist: Arc::new(allowlist),
                audit: audit.clone(),
            };
            let router = http::router(state);
            let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
            tracing::info!(addr = %bind_addr, "slack events endpoint started");
            tokio::spawn(async move {
                if let Err(e) = axum::serve(listener, router).await {
                    tracing::error!(error = %e, "slack events server failed");
                }
            });
            Some(relay)
        }
        None => None,
    };

    let dispatcher = Arc::new(DualChannelDispatcher { cli, slack, audit });
    tokio::spawn(symbi_bridge::bridge(dispatcher, symbi_rx));
    Ok(())
}

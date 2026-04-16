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
pub mod types;

pub use config::SlackApprovalConfig;
pub use dispatcher::DualChannelDispatcher;
pub use types::{ApprovalDecision, ApprovalRequest, Approver, Outcome, RiskTier};

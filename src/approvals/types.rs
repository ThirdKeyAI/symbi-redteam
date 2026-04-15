use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    Medium,
    MediumHigh,
    High,
    Highest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub request_id: Uuid,
    pub engagement_id: String,
    pub agent_name: String,
    pub tool: String,
    pub args_redacted: serde_json::Value,
    pub target: String,
    pub risk_tier: RiskTier,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Approve,
    Deny,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "channel", rename_all = "snake_case")]
pub enum Approver {
    Cli { user: String },
    Slack { user_id: String, message_ts: String },
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDecision {
    pub request_id: Uuid,
    pub outcome: Outcome,
    pub approver: Approver,
    pub reason: Option<String>,
    pub decided_at: DateTime<Utc>,
}

impl ApprovalDecision {
    pub fn approved(&self) -> bool {
        matches!(self.outcome, Outcome::Approve)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approver_serializes_with_channel_tag() {
        let a = Approver::Slack {
            user_id: "U01ABC".into(),
            message_ts: "1700000000.000100".into(),
        };
        let json = serde_json::to_value(&a).unwrap();
        assert_eq!(json["channel"], "slack");
        assert_eq!(json["user_id"], "U01ABC");
    }

    #[test]
    fn risk_tier_serializes_snake_case() {
        let json = serde_json::to_string(&RiskTier::MediumHigh).unwrap();
        assert_eq!(json, "\"medium_high\"");
    }

    #[test]
    fn decision_approved_flag() {
        let d = ApprovalDecision {
            request_id: Uuid::nil(),
            outcome: Outcome::Approve,
            approver: Approver::System,
            reason: None,
            decided_at: Utc::now(),
        };
        assert!(d.approved());
    }
}

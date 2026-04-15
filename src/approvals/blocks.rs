use crate::approvals::types::{ApprovalDecision, ApprovalRequest, Approver, Outcome};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

pub fn request_blocks(req: &ApprovalRequest) -> Value {
    let args_pretty = serde_json::to_string_pretty(&req.args_redacted).unwrap_or_default();
    let truncated = if args_pretty.len() > 1500 {
        format!("{}…\n[truncated]", &args_pretty[..1500])
    } else {
        args_pretty
    };
    json!([
        {
            "type": "header",
            "text": { "type": "plain_text",
                      "text": format!(":lock: Approval required — {} [{:?}]", req.tool, req.risk_tier) }
        },
        {
            "type": "section",
            "fields": [
                { "type": "mrkdwn", "text": format!("*Engagement*\n`{}`", req.engagement_id) },
                { "type": "mrkdwn", "text": format!("*Agent*\n`{}`", req.agent_name) },
                { "type": "mrkdwn", "text": format!("*Target*\n`{}`", req.target) },
                { "type": "mrkdwn", "text": format!("*Expires*\n<!date^{}^{{date_short_pretty}} {{time}}|{}>",
                    req.expires_at.timestamp(), req.expires_at.to_rfc3339()) },
            ]
        },
        {
            "type": "section",
            "text": { "type": "mrkdwn", "text": format!("*Args (redacted)*\n```{}```", truncated) }
        },
        {
            "type": "actions",
            "block_id": format!("approval:{}", req.request_id),
            "elements": [
                { "type": "button", "style": "primary",
                  "text": { "type": "plain_text", "text": "Approve" },
                  "action_id": format!("approve:{}", req.request_id),
                  "value": req.request_id.to_string() },
                { "type": "button", "style": "danger",
                  "text": { "type": "plain_text", "text": "Deny" },
                  "action_id": format!("deny:{}", req.request_id),
                  "value": req.request_id.to_string() },
            ]
        }
    ])
}

pub fn resolved_footer(decision: &ApprovalDecision) -> Value {
    let label = match (&decision.outcome, &decision.approver) {
        (Outcome::Approve, Approver::Slack { user_id, .. }) =>
            format!(":white_check_mark: Approved by <@{}>", user_id),
        (Outcome::Approve, Approver::Cli { user }) =>
            format!(":white_check_mark: Approved via CLI by `{}`", user),
        (Outcome::Deny, Approver::Slack { user_id, .. }) =>
            format!(":no_entry: Denied by <@{}>", user_id),
        (Outcome::Deny, Approver::Cli { user }) =>
            format!(":no_entry: Denied via CLI by `{}`", user),
        (Outcome::Expired, _) => ":hourglass: Expired".to_string(),
        (_, Approver::System) => ":gear: Resolved by system".to_string(),
    };
    json!({
        "type": "context",
        "elements": [{ "type": "mrkdwn",
                       "text": format!("{} at <!date^{}^{{time}}|{}>",
                                       label, decision.decided_at.timestamp(),
                                       decision.decided_at.to_rfc3339()) }]
    })
}

pub fn expired_footer(expires_at: DateTime<Utc>) -> Value {
    json!({
        "type": "context",
        "elements": [{ "type": "mrkdwn",
                       "text": format!(":hourglass: Expired at <!date^{}^{{time}}|{}>",
                                       expires_at.timestamp(), expires_at.to_rfc3339()) }]
    })
}

pub fn dm_blocks(req: &ApprovalRequest, channel_permalink: &str) -> Value {
    json!([
        { "type": "section",
          "text": { "type": "mrkdwn",
                    "text": format!(":lock: Approval needed: *{}* on `{}` (engagement `{}`).\n<{}|Open in channel>",
                                    req.tool, req.target, req.engagement_id, channel_permalink) } }
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approvals::types::RiskTier;
    use uuid::Uuid;

    fn req() -> ApprovalRequest {
        ApprovalRequest {
            request_id: Uuid::from_u128(1),
            engagement_id: "eng-1".into(),
            agent_name: "exploit".into(),
            tool: "metasploit_run".into(),
            args_redacted: serde_json::json!({"module": "exploit/multi/handler", "rhost": "10.0.1.5"}),
            target: "10.0.1.5".into(),
            risk_tier: RiskTier::High,
            requested_at: Utc::now(),
            expires_at: Utc::now(),
        }
    }

    #[test]
    fn request_blocks_have_action_id_with_uuid() {
        let v = request_blocks(&req());
        let actions = v[3]["elements"].as_array().unwrap();
        let approve = &actions[0];
        assert_eq!(approve["action_id"], format!("approve:{}", Uuid::from_u128(1)));
        let deny = &actions[1];
        assert_eq!(deny["action_id"], format!("deny:{}", Uuid::from_u128(1)));
    }

    #[test]
    fn resolved_footer_for_slack_approval() {
        let d = ApprovalDecision {
            request_id: Uuid::nil(),
            outcome: Outcome::Approve,
            approver: Approver::Slack { user_id: "U99".into(), message_ts: "1.2".into() },
            reason: None,
            decided_at: Utc::now(),
        };
        let v = resolved_footer(&d);
        let text = v["elements"][0]["text"].as_str().unwrap();
        assert!(text.contains("Approved by <@U99>"));
    }

    #[test]
    fn expired_footer_renders() {
        let v = expired_footer(Utc::now());
        let text = v["elements"][0]["text"].as_str().unwrap();
        assert!(text.contains("Expired"));
    }
}

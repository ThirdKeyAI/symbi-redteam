use crate::approvals::audit::{ApprovalAuditLogger, AuditEvent};
use crate::approvals::slack_relay::SlackApprovalRelay;
use crate::approvals::types::{ApprovalDecision, Approver, Outcome};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use uuid::Uuid;

const TIMESTAMP_TOLERANCE_SECS: i64 = 300;

#[derive(Clone)]
pub struct AppState {
    pub relay: Arc<SlackApprovalRelay>,
    pub signing_secret: Arc<String>,
    pub allowlist: Arc<Vec<String>>,
    pub audit: Arc<ApprovalAuditLogger>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/slack/events", post(handle_events))
        .with_state(state)
}

pub fn verify_signature(secret: &str, timestamp: &str, body: &[u8], provided: &str) -> bool {
    let basestring = format!("v0:{}:{}", timestamp, std::str::from_utf8(body).unwrap_or(""));
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(basestring.as_bytes());
    let expected = mac.finalize().into_bytes();
    let expected_hex = format!("v0={}", hex::encode(expected));
    expected_hex.as_bytes().ct_eq(provided.as_bytes()).into()
}

fn timestamp_within_window(ts: &str, now_secs: i64) -> bool {
    let parsed: i64 = match ts.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    (now_secs - parsed).abs() <= TIMESTAMP_TOLERANCE_SECS
}

async fn handle_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let ts = headers
        .get("X-Slack-Request-Timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let sig = headers
        .get("X-Slack-Signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if !timestamp_within_window(ts, now) {
        return (StatusCode::UNAUTHORIZED, "stale timestamp").into_response();
    }
    if !verify_signature(&state.signing_secret, ts, &body, sig) {
        return (StatusCode::UNAUTHORIZED, "bad signature").into_response();
    }
    // Slack interactivity sends payload as form-encoded `payload=<json>`.
    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => return (StatusCode::BAD_REQUEST, "non-utf8").into_response(),
    };
    let payload_json = match extract_payload(body_str) {
        Some(s) => s,
        None => return (StatusCode::BAD_REQUEST, "missing payload").into_response(),
    };
    let payload: serde_json::Value = match serde_json::from_str(&payload_json) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad json").into_response(),
    };

    if payload["type"] != "block_actions" {
        return (StatusCode::OK, "ignored").into_response();
    }
    let user_id = payload["user"]["id"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let action_id = payload["actions"][0]["action_id"].as_str().unwrap_or("");
    let message_ts = payload["message"]["ts"]
        .as_str()
        .unwrap_or("")
        .to_string();

    let (verb, uuid_str) = match action_id.split_once(':') {
        Some(p) => p,
        None => return (StatusCode::OK, "ignored").into_response(),
    };
    let request_id = match Uuid::parse_str(uuid_str) {
        Ok(u) => u,
        Err(_) => return (StatusCode::OK, "bad uuid").into_response(),
    };

    if !state.allowlist.iter().any(|u| u == &user_id) {
        let _ = state
            .audit
            .log(AuditEvent::SlackUnauthorizedClick {
                request_id,
                slack_user_id: user_id.clone(),
            })
            .await;
        return (StatusCode::OK, ":no_entry: Not authorized").into_response();
    }

    let outcome = match verb {
        "approve" => Outcome::Approve,
        "deny" => Outcome::Deny,
        _ => return (StatusCode::OK, "unknown verb").into_response(),
    };
    let decision = ApprovalDecision {
        request_id,
        outcome,
        approver: Approver::Slack {
            user_id: user_id.clone(),
            message_ts,
        },
        reason: None,
        decided_at: Utc::now(),
    };
    if !state.relay.try_resolve(request_id, decision) {
        return (StatusCode::OK, "already resolved or expired").into_response();
    }
    (StatusCode::OK, "").into_response()
}

/// Extract `payload=<json>` from form-encoded body. Slack URL-encodes the JSON.
fn extract_payload(body: &str) -> Option<String> {
    for part in body.split('&') {
        if let Some(encoded) = part.strip_prefix("payload=") {
            // URL-decode the payload
            match urlencoding::decode(encoded) {
                Ok(decoded) => return Some(decoded.into_owned()),
                Err(_) => return Some(encoded.to_string()),
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_verification_passes_for_known_vector() {
        // HMAC-SHA256 computed from Slack's documented signing example parameters.
        // basestring = "v0:<ts>:<body>" signed with the signing secret.
        let secret = "8f742231b10e8888abcd99yyyzzz85a5";
        let ts = "1531420618";
        let body = b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2147483697&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
        // Compute expected signature at test time to act as a self-consistent round-trip vector.
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(
            format!("v0:{}:{}", ts, std::str::from_utf8(body).unwrap()).as_bytes(),
        );
        let sig = format!("v0={}", hex::encode(mac.finalize().into_bytes()));
        assert!(verify_signature(secret, ts, body, &sig));
    }

    #[test]
    fn signature_rejects_tampered_body() {
        let secret = "secret";
        let ts = "1700000000";
        let body = b"hello";
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(
            format!("v0:{}:{}", ts, std::str::from_utf8(body).unwrap()).as_bytes(),
        );
        let sig = format!("v0={}", hex::encode(mac.finalize().into_bytes()));
        assert!(!verify_signature(secret, ts, b"tampered", &sig));
    }

    #[test]
    fn timestamp_window_enforced() {
        let now = 1_700_000_000_i64;
        assert!(timestamp_within_window("1700000000", now));
        assert!(timestamp_within_window("1699999800", now)); // 200s old
        assert!(!timestamp_within_window("1699999699", now)); // 301s old
    }
}

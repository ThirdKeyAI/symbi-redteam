use serde::{Deserialize, Serialize};
use std::env::VarError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackApprovalConfig {
    #[serde(default)]
    pub enabled: bool,
    pub bot_token_env: String,
    pub app_token_env: Option<String>,
    pub signing_secret_env: String,
    pub channel: String,
    #[serde(default)]
    pub approvers: Vec<String>,
    #[serde(default = "default_dm")]
    pub dm_approvers: bool,
    #[serde(default = "default_bind")]
    pub events_bind_addr: String,
}

fn default_dm() -> bool { true }
fn default_bind() -> String { "0.0.0.0:9082".into() }

#[derive(Debug, Clone)]
pub struct ResolvedSlackConfig {
    pub bot_token: String,
    pub signing_secret: String,
    pub channel: String,
    pub approvers: Vec<String>,
    pub dm_approvers: bool,
    pub events_bind_addr: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("env var {0} missing or invalid: {1}")]
    EnvVar(String, VarError),
    #[error("approvers list is empty")]
    NoApprovers,
    #[error("channel must be non-empty")]
    EmptyChannel,
}

impl SlackApprovalConfig {
    pub fn resolve(&self) -> Result<ResolvedSlackConfig, ConfigError> {
        if self.channel.is_empty() {
            return Err(ConfigError::EmptyChannel);
        }
        if self.approvers.is_empty() {
            return Err(ConfigError::NoApprovers);
        }
        let bot_token = std::env::var(&self.bot_token_env)
            .map_err(|e| ConfigError::EnvVar(self.bot_token_env.clone(), e))?;
        let signing_secret = std::env::var(&self.signing_secret_env)
            .map_err(|e| ConfigError::EnvVar(self.signing_secret_env.clone(), e))?;
        Ok(ResolvedSlackConfig {
            bot_token,
            signing_secret,
            channel: self.channel.clone(),
            approvers: self.approvers.clone(),
            dm_approvers: self.dm_approvers,
            events_bind_addr: self.events_bind_addr.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> SlackApprovalConfig {
        SlackApprovalConfig {
            enabled: true,
            bot_token_env: "TEST_BOT".into(),
            app_token_env: None,
            signing_secret_env: "TEST_SECRET".into(),
            channel: "#approvals".into(),
            approvers: vec!["U01".into()],
            dm_approvers: true,
            events_bind_addr: "0.0.0.0:9082".into(),
        }
    }

    #[test]
    fn rejects_empty_approvers() {
        let mut c = base();
        c.approvers.clear();
        assert!(matches!(c.resolve(), Err(ConfigError::NoApprovers)));
    }

    #[test]
    fn rejects_missing_env() {
        // ensure the var is unset for this test
        std::env::remove_var("DEFINITELY_NOT_SET_XYZ");
        let mut c = base();
        c.bot_token_env = "DEFINITELY_NOT_SET_XYZ".into();
        std::env::set_var("TEST_SECRET", "s");
        assert!(matches!(c.resolve(), Err(ConfigError::EnvVar(_, _))));
    }

    #[test]
    fn resolves_when_env_present() {
        std::env::set_var("TEST_BOT", "xoxb-test");
        std::env::set_var("TEST_SECRET", "secret");
        let resolved = base().resolve().unwrap();
        assert_eq!(resolved.bot_token, "xoxb-test");
        assert_eq!(resolved.signing_secret, "secret");
        assert_eq!(resolved.channel, "#approvals");
    }
}

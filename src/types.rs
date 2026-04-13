use serde::{Deserialize, Serialize};

// =============================================================================
// ToolError -- error type for MCP tool functions
// =============================================================================

#[derive(Debug)]
pub enum ToolError {
    InvalidInput(String),
    ExecutionFailed(String),
    ParseError(String),
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolError::InvalidInput(msg) => write!(f, "Invalid input: {msg}"),
            ToolError::ExecutionFailed(msg) => write!(f, "Execution failed: {msg}"),
            ToolError::ParseError(msg) => write!(f, "Parse error: {msg}"),
        }
    }
}

impl std::error::Error for ToolError {}

// =============================================================================
// ToolDefinition -- MCP tool registration with Cedar policy metadata
//
// The Symbiont runtime's ToolDefinition is minimal (name, description,
// parameters). This local type extends it with Cedar resource/action
// mappings, human-gate flags, and scope revalidation markers that the
// ORGA gate uses for policy evaluation.
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
    #[serde(default)]
    pub cedar_resource: Option<String>,
    #[serde(default)]
    pub cedar_actions: Vec<String>,
    #[serde(default)]
    pub policy_gate: bool,
    #[serde(default)]
    pub human_gate: bool,
    #[serde(default)]
    pub human_gate_required: bool,
    #[serde(default)]
    pub scope_revalidated: bool,
}

impl ToolDefinition {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            description: String::new(),
            parameters: serde_json::json!({}),
            cedar_resource: None,
            cedar_actions: Vec::new(),
            policy_gate: true,
            human_gate: false,
            human_gate_required: false,
            scope_revalidated: false,
        }
    }

    pub fn description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn input_schema<T: serde::Serialize + Default>(mut self) -> Self {
        if let Ok(val) = serde_json::to_value(T::default()) {
            self.parameters = val;
        }
        self
    }

    pub fn cedar_resource(mut self, resource: &str) -> Self {
        self.cedar_resource = Some(resource.to_string());
        self
    }

    pub fn cedar_actions(mut self, actions: &[&str]) -> Self {
        self.cedar_actions = actions.iter().map(|a| a.to_string()).collect();
        self
    }

    pub fn no_policy_gate(mut self) -> Self {
        self.policy_gate = false;
        self
    }

    pub fn human_gated(mut self) -> Self {
        self.human_gate = true;
        self
    }

    pub fn human_gate_required(mut self) -> Self {
        self.human_gate_required = true;
        self
    }

    pub fn scope_revalidated(mut self) -> Self {
        self.scope_revalidated = true;
        self
    }
}

// =============================================================================
// Input validation helpers -- defense-in-depth for tool arguments
//
// Wrapper scripts also validate, but the Rust layer should reject obviously
// bad input before spawning a subprocess.
// =============================================================================

/// Validate that a string matches UUID format (hex + hyphens, 36 chars).
/// Also accepts the `eng-*` prefix format used by engagement IDs.
pub fn validate_engagement_id(id: &str) -> Result<(), ToolError> {
    // Accept UUID v4 format or eng-prefix format
    let valid = id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && !id.is_empty()
        && id.len() <= 64
        && !id.contains("..");
    if !valid {
        return Err(ToolError::InvalidInput(
            format!("Invalid engagement ID: must be alphanumeric/hyphens/underscores, got '{id}'")
        ));
    }
    Ok(())
}

/// Validate that a file path is confined under an allowed prefix and contains
/// no traversal sequences. Resolves the path to catch symlink escapes.
pub fn validate_confined_path(path: &str, allowed_prefix: &str) -> Result<String, ToolError> {
    if path.contains("..") {
        return Err(ToolError::InvalidInput(
            format!("Path traversal detected: '{path}'")
        ));
    }
    // Canonicalize if the path exists (catches symlinks), otherwise validate prefix
    let resolved = if std::path::Path::new(path).exists() {
        std::fs::canonicalize(path)
            .map_err(|e| ToolError::InvalidInput(format!("Cannot resolve path '{path}': {e}")))?
            .to_string_lossy()
            .to_string()
    } else {
        path.to_string()
    };
    if !resolved.starts_with(allowed_prefix) {
        return Err(ToolError::InvalidInput(
            format!("Path '{resolved}' is not under allowed prefix '{allowed_prefix}'")
        ));
    }
    Ok(resolved)
}

/// Validate that a value is one of the allowed options.
pub fn validate_allowlist(value: &str, field_name: &str, allowed: &[&str]) -> Result<(), ToolError> {
    if !allowed.contains(&value) {
        return Err(ToolError::InvalidInput(
            format!("Invalid {field_name}: '{value}'. Allowed: {}", allowed.join(", "))
        ));
    }
    Ok(())
}

/// Validate a port range string (digits, commas, hyphens only).
pub fn validate_port_range(range: &str) -> Result<(), ToolError> {
    if range.is_empty() || !range.chars().all(|c| c.is_ascii_digit() || c == ',' || c == '-') {
        return Err(ToolError::InvalidInput(
            format!("Invalid port range: '{range}'. Must contain only digits, commas, and hyphens")
        ));
    }
    Ok(())
}

/// Validate that a string contains no shell-dangerous or path-traversal characters.
pub fn validate_safe_identifier(value: &str, field_name: &str) -> Result<(), ToolError> {
    if value.is_empty() {
        return Err(ToolError::InvalidInput(format!("{field_name} must not be empty")));
    }
    if !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return Err(ToolError::InvalidInput(
            format!("Invalid {field_name}: '{value}'. Must be alphanumeric, underscores, hyphens, or dots")
        ));
    }
    if value.contains("..") {
        return Err(ToolError::InvalidInput(
            format!("{field_name} must not contain '..'")
        ));
    }
    Ok(())
}

/// Validate nmap script names (comma-separated alphanumeric with hyphens/underscores).
pub fn validate_nmap_scripts(scripts: &str) -> Result<(), ToolError> {
    if scripts.is_empty() {
        return Err(ToolError::InvalidInput("scripts must not be empty".to_string()));
    }
    if !scripts.chars().all(|c| c.is_ascii_alphanumeric() || c == ',' || c == '-' || c == '_' || c == '*') {
        return Err(ToolError::InvalidInput(
            format!("Invalid scripts: '{scripts}'. Must contain only alphanumeric, commas, hyphens, underscores, and wildcards")
        ));
    }
    Ok(())
}

/// Validate a URL for basic safety (no shell chars, no newlines).
pub fn validate_url(url: &str) -> Result<(), ToolError> {
    if url.is_empty() {
        return Err(ToolError::InvalidInput("URL must not be empty".to_string()));
    }
    let dangerous = [';', '|', '&', '$', '`', '\n', '\r', '\0'];
    for c in dangerous {
        if url.contains(c) {
            return Err(ToolError::InvalidInput(
                format!("URL contains dangerous character: '{}'", c.escape_default())
            ));
        }
    }
    Ok(())
}

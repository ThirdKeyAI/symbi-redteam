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

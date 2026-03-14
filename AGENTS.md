# AGENTS.md -- AI Agent Instructions for symbi-nmap-agent

## Project Overview

This repository demonstrates adding AI-governed intelligence to nmap using the Symbiont trust stack. The agent wraps nmap's scanning capabilities with ORGA loop governance, Cedar policy enforcement, and cryptographic audit trails.

## Architecture

The system has four layers:

1. **nmap** (dumb tool): Executes network scans. Has no concept of authorization, proportionality, or audit.
2. **Wrapper scripts** (`scripts/`): Sanitize arguments, capture output, enforce timeouts. Defense in depth.
3. **MCP tools** (`src/tools.rs`): Define the interface between the LLM and nmap. Each tool call is intercepted by the ORGA Gate.
4. **Symbiont runtime**: Runs the ORGA loop. The Gate phase evaluates Cedar policies in `policies/` before any tool executes.

## Key Files

| File | Purpose | When to modify |
|---|---|---|
| `agents/nmap-recon.dsl` | Agent definition | Adding behaviors, changing capabilities, adjusting prompts |
| `policies/scan-authorization.cedar` | Target and scan type rules | Adding/removing allowed CIDRs or scan types |
| `policies/rate-limits.cedar` | Frequency limits | Adjusting scan rate limits |
| `policies/escalation.cedar` | Human approval rules | Changing which scans need approval |
| `src/tools.rs` | MCP tool definitions | Adding new tools or modifying tool schemas |
| `scripts/nmap-wrapper.sh` | nmap execution | Changing scan flags or output handling |
| `scripts/parse-nmap-xml.py` | Output parsing | Supporting new nmap output fields |
| `Dockerfile` | Container image | Adding dependencies or changing base image |
| `symbi.toml` | Runtime config | Tuning timeouts, models, or security settings |

## Development Rules

1. **Never bypass the Gate.** If a tool needs to execute without policy checks, use `.no_policy_gate()` in the tool registration and document why.
2. **Capabilities are explicit.** If the agent needs a new capability, add it to both the DSL `capabilities` list and the relevant Cedar policies.
3. **Defense in depth.** The wrapper script validates arguments even though Cedar already authorized the scan. Bugs happen.
4. **Cedar policies are the source of truth.** The DSL `policy` blocks are hints; the `.cedar` files in `policies/` are what the runtime actually evaluates.
5. **Test policy changes with `symbi policy evaluate`.** Don't deploy Cedar changes without running the policy simulator.

## Common Tasks

### Add a new allowed scan target
Edit `policies/scan-authorization.cedar` and add a `permit` rule for the new CIDR.

### Add a new scan type
1. Add the nmap flags to `scripts/nmap-wrapper.sh`
2. Add Cedar policies governing when the type is allowed
3. Update the DSL `scan_type_governance` policy block
4. Test with `symbi policy evaluate`

### Add a new tool
1. Define input/output structs in `src/tools.rs`
2. Implement the tool function
3. Register it in `register_tools()` with appropriate Cedar resource/action mappings
4. Add the capability to the DSL agent definition
5. Write Cedar policies for the new tool

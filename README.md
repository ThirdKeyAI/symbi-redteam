# symbi-redteam

<p align="center">
  <img src="symbi-redteam.png" alt="symbi-redteam" width="300">
</p>

**Governed red-team automation for authorized security validation.**

`symbi-redteam` is a Symbiont-native red-team harness for running AI-assisted offensive-security workflows under explicit scope, policy, approval, and audit controls.

It is designed for environments where agents may help with reconnaissance, enumeration, vulnerability validation, evidence collection, retesting, and reporting, but may not act outside authorized boundaries. Agents can propose actions. Symbiont decides what is allowed to execute.

Every tool invocation is mediated through ToolClad contracts, Cedar authorization, engagement scope, risk-tier rules, time bounds, evidence capture, and tamper-evident audit logging. High-risk exploitation and post-exploitation actions require human approval before execution.

> **Authorized use only.**
> This project is intended for owned labs, internal security programs, and explicitly authorized client engagements. Do not use it against systems you do not own or have written permission to test.

---

## Why this exists

AI can accelerate security testing, but offensive workflows are high-risk.

A scan can cross scope.
A model can hallucinate permission.
A tool can become destructive.
A finding can lose its evidence trail.
A junior operator or autonomous agent can run the wrong action.
A report can omit the policy, approval, and tool context behind a result.

For regulated or high-assurance teams, "the agent decided to run it" is not an acceptable control.

`symbi-redteam` exists to make red-team automation governable:

- scope is enforced, not suggested
- high-risk actions are human-gated
- tools are exposed through typed contracts
- every action is policy-checked before execution
- every result is tied to evidence
- every policy decision is audit logged
- every engagement can be reconstructed after the fact

---

## Core principle

**Agents may propose offensive actions. They do not authorize them.**

The Symbiont runtime sits between model intent and real-world execution:

```text
agent observes
      ↓
agent reasons
      ↓
agent proposes action
      ↓
Symbiont Gate evaluates policy
      ↓
allow, deny, modify, rate-limit, or require approval
      ↓
approved action executes
      ↓
evidence and audit records are written
```

The Gate operates outside the LLM. A model can reason about a Metasploit module, a credential attack, or a post-exploitation step, but it cannot grant itself permission to run one.

---

## What it is

`symbi-redteam` is a governed red-team execution system built on [Symbiont](https://github.com/ThirdKeyAI/symbiont).

It combines:

* a methodology-aware engagement controller
* phase-specific agents for recon, enumeration, vulnerability assessment, validation, exploitation, post-exploitation, and reporting
* a read-only validate agent that adjudicates findings under strict separation of duties
* a bounded reflector that distils each phase's lessons into a knowledge store the next phase reads
* Cedar policy gates for scope, phase order, tool risk, time bounds, rate limits, approvals, and validation separation of duties
* ToolClad manifests for typed tool contracts and MCP schema generation
* shell wrappers around offensive tools for argument validation, timeouts, and JSON output
* evidence storage with SHA-256 integrity metadata
* tamper-evident audit logs for every tool call and policy decision
* optional Slack approval workflows for human-gated actions
* OpenTelemetry tracing for engagement replay and debugging

---

## What it is not

`symbi-redteam` is not:

* an unsupervised attack bot
* a general-purpose malware or exploitation framework
* a tool for unauthorized scanning
* a replacement for experienced operators
* a substitute for engagement scoping, legal authorization, or client approval
* a promise that AI-generated findings are correct without validation

It is a governed automation harness for authorized security testing.

---

## Relationship to private upstream analysis

`symbi-redteam` can run standalone from a manually defined engagement scope.

It can also consume signed validation objectives from private upstream analysis systems, including ThirdKey's private CodeRed pipeline when available.

The intended closed-loop workflow is:

```text
source or system finding
        ↓
signed validation objective
        ↓
scope and policy compilation
        ↓
governed red-team validation
        ↓
evidence-backed result
        ↓
report, retest plan, and audit trail
```

This keeps discovery, validation, evidence, and reporting connected without giving agents unchecked execution authority.

---

## High-level workflow

```text
engagement scope
      ↓
policy loading
      ↓
controller creates phase plan
      ↓
recon
      ↓
enumeration
      ↓
vulnerability assessment
      ↓
read-only validation (adjudicates findings)
      ↓
human-gated exploitation
      ↓
human-gated post-exploitation
      ↓
final validation before reporting
      ↓
reporting and retest comparison
```

Between phases the controller invokes a bounded **reflector** that reads the phase's findings and writes subject-predicate-object lessons to a knowledge store; the next phase recalls them before planning. Lessons flow forward, but tool authority does not expand automatically.

---

## Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│                    Engagement Controller                     │
│  Maintains state, enforces methodology, orchestrates phases   │
└──────┬──────────┬──────────┬──────────┬──────────┬───────────┘
       │          │          │          │          │
 ┌─────▼────┐ ┌───▼────┐ ┌───▼────┐ ┌───▼────┐ ┌───▼──────┐
 │  Recon   │ │  Enum  │ │  Vuln  │ │Validate│ │ Reporter │
 │  Agent   │ │ Agent  │ │ Agent  │ │ Agent  │ │  Agent   │
 └─────┬────┘ └───┬────┘ └───┬────┘ └───┬────┘ └───┬──────┘
       │          │          │          │          │
       └──────────┴────┬─────┴──────────┴──────────┘
                       │   (Exploit / Post-Exploit agents are human-gated)
                ┌──────▼───────┐
                │   Reflector  │
                │ bounded memory│
                └──────┬───────┘
                       │
┌──────────────────────▼───────────────────────────────────────┐
│                      Symbiont Runtime                        │
│                                                              │
│  ORGA loop                                                   │
│  Cedar Gate                                                  │
│  ToolClad contracts                                          │
│  MCP tool registration                                       │
│  sandbox and timeout controls                                │
│  audit journal                                               │
│  approval routing                                            │
│  telemetry                                                   │
└──────────────────────┬───────────────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────────────┐
│                       Tool Layer                             │
│                                                              │
│  typed arguments                                             │
│  scope validation                                            │
│  rate limits                                                 │
│  JSON output                                                 │
│  evidence capture                                            │
│  SHA-256 integrity metadata                                  │
└──────────────────────┬───────────────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────────────┐
│                  Authorized Security Toolchain (Kali)        │
│                                                              │
│  nmap · nikto · nuclei · sqlmap · hydra · metasploit         │
│  impacket · pypykatz · chisel · ligolo · gobuster · ...      │
└──────────────────────────────────────────────────────────────┘
```

---

## Agents

The engagement controller orchestrates nine agents in a hierarchical tree. Phase
agents do not receive global tool authority; each gets only the tools and
context its phase needs.

| Agent | Role | Typical authority |
| --------------------- | --------------------------------------------------- | ---------------------------------------------- |
| `engagement-controller` | Maintains state, selects phases, routes work via `ask()` | Orchestration only |
| `recon`               | Discovers authorized assets and services            | Low-risk tools within scope                    |
| `enum`                | Service and application enumeration                 | Medium-risk tools with rate limits             |
| `vuln-assess`         | Correlates likely weaknesses and candidate checks   | Medium-high tools, usually non-production only |
| `validate`            | Read-only adjudication of findings; the only principal that may flip `verified` / `false_positive` | Read-only; `verify_finding` and `mark_false_positive` only, structurally denied `store_finding` |
| `exploit`             | Validates exploitability when authorized            | Human approval required                        |
| `post-exploit`        | Bounded post-exploitation checks                    | Human approval and scope revalidation required |
| `reflector`           | Distils phase lessons into small knowledge triples  | Knowledge tools only                           |
| `reporter`            | Builds executive, technical, and remediation output; produces retest deltas via `compare_engagements` | Read-only evidence and findings access         |

Retesting is not a separate agent: the reporter's `compare_engagements` tool
takes a current and a baseline engagement ID and produces a delta report
showing remediated, persistent, regressed, and new findings.

---

## Risk-tiered authorization

Tools are not exposed directly to agents. They are wrapped as governed capabilities.

| Risk tier   | Examples                                                                            | Default authorization                                                 |
| ----------- | ----------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Low         | nmap, whois, DNS, whatweb, amass — passive recon and service discovery within scope | Auto-allowed within engagement scope                                  |
| Medium      | nikto, gobuster, enum4linux, smbclient, snmpwalk — web and service enumeration       | Rate-limited and logged                                               |
| Medium-high | nmap NSE, nuclei, sqlmap (detect), searchsploit — vulnerability checks               | Restricted by environment and phase                                   |
| High        | hydra, metasploit, sqlmap (exploit/dump) — exploit validation and password attacks   | Human approval required                                               |
| Highest     | impacket, pypykatz, chisel, ligolo — post-exploitation, credentials, tunneling       | Human approval, scope revalidation, and tighter evidence requirements |

Risk tiers are policy decisions, not prompt instructions.

---

## Cedar policy model

Nine Cedar policies enforce governance across the engagement. The `.cedar` files
in `policies/` are the source of truth; DSL `policy` blocks in the agents are
hints only.

| Policy file                | Purpose                                                                          |
| -------------------------- | -------------------------------------------------------------------------------- |
| `scope.cedar`              | Enforces target CIDRs, allowed hosts, excluded assets, and engagement boundaries |
| `tool-authorization.cedar` | Maps tools and actions to risk tiers and authorization requirements              |
| `phase-gates.cedar`        | Enforces PTES phase order and methodology constraints                            |
| `rate-limits.cedar`        | Controls per-target and global frequency limits                                  |
| `escalation.cedar`         | Requires time-limited human approval for high-risk actions                       |
| `evidence.cedar`           | Requires evidence envelopes for findings; gates report generation on verified findings |
| `time-bounds.cedar`        | Enforces engagement start and end windows                                        |
| `validation.cedar`         | Separation of duties: only the `validate` principal may verify findings, and it is structurally denied `store_finding` |
| `reflector.cedar`          | Restricts the reflector to `store_knowledge` / `recall_knowledge` / `query_findings` via a defensive `forbid ... unless` |

Example intent:

```cedar
forbid(
    principal,
    action == Action::"run_tool",
    resource
) when {
    resource.target not in principal.engagement.allowed_targets
};
```

Example high-risk approval pattern:

```cedar
permit(
    principal,
    action == Action::"run_tool",
    resource
) when {
    resource.risk == "high" &&
    context.approval.status == "approved" &&
    context.approval.expires_at > context.now
};
```

Policies are deployment-specific. Treat the examples as patterns, not production policy. Validate changes with `symbi policy evaluate` before every engagement.

---

## Data model

`SQLite` stores structured engagement state:

* engagements
* targets
* tool runs
* findings
* finding verifications (validate-agent decisions)
* retests
* approvals
* evidence references
* reflector-authored knowledge triples

`LanceDB` provides semantic search and correlation across evidence and findings, so a service that moved ports or a finding described differently by another scanner still gets matched.

The knowledge store records small subject-predicate-object lessons, for example:

```text
(service:10.0.2.15:445, allows, smb_null_session, confidence=0.9)
(web:app.local, moved_from, 8080, confidence=0.8)
(finding:abc123, related_to, weak_default_credentials, confidence=0.7)
```

The triple shape keeps phase-to-phase learning concrete and small enough to inject into later prompts without giving agents broader authority. The pattern is borrowed from [symbiont-karpathy-loop](https://github.com/ThirdKeyAI/symbiont-karpathy-loop).

The evidence store archives tool output with integrity metadata:

```json
{
  "evidence_id": "ev_01J...",
  "engagement_id": "eng_01J...",
  "tool": "nmap_scan",
  "target": "10.0.2.15",
  "sha256": "9f2c...",
  "created_at": "2026-05-21T20:11:08Z",
  "policy_decision": "allow",
  "approval_id": null
}
```

---

## Outputs

A completed engagement can produce:

| Artifact            | Purpose                                                     |
| ------------------- | ----------------------------------------------------------- |
| `report.md`         | Human-readable executive and technical report               |
| `findings.json`     | Structured findings and validation status                   |
| `evidence/`         | Raw tool outputs with integrity metadata                    |
| `audit.jsonl`       | Hash-chained audit trail of policy decisions and tool calls |
| retest delta report | Remediated / persistent / regressed / new findings via `compare_engagements` |
| `approvals.json`    | Human approval records and expiry metadata                  |
| `trace-export.json` | Optional OpenTelemetry trace export                         |

Validation status values should be explicit:

| Status              | Meaning                                                                   |
| ------------------- | ------------------------------------------------------------------------- |
| `verified`          | Evidence supports exploitability or real exposure                         |
| `not_reproduced`    | The system did not reproduce the issue under current scope and conditions |
| `false_positive`    | The validate agent adjudicated the finding as not real                    |
| `inconclusive`      | Testing could not complete or evidence was insufficient                   |
| `out_of_scope`      | Objective was outside the engagement boundary                             |
| `blocked_by_policy` | Policy denied the requested action                                        |
| `requires_approval` | Human approval is required before continuing                              |
| `mitigated`         | Retest indicates remediation is effective                                 |

`generate_report` is gated by `evidence.cedar` on the unverified critical/high
count reaching zero, so reporting cannot run until the validate agent has
adjudicated the high-severity findings.

---

## Quick start

### Prerequisites

* Docker
* An Anthropic API key
* An explicit test scope
* A lab or authorized environment

### Clone

```bash
git clone https://github.com/ThirdKeyAI/symbi-redteam.git
cd symbi-redteam
```

### Configure environment

Set the required values in your shell (in production, use a secrets manager rather than env vars):

```bash
export ANTHROPIC_API_KEY=your-key
export SYMBIONT_API_TOKEN=change-me
export SYMBIONT_MASTER_KEY=$(openssl rand -hex 32)
export SYMBI_LOG_LEVEL=info
```

### Configure scope

Edit `scope/scope.toml`. The scope is loaded at engagement start and injected
into Cedar policy evaluation as entity attributes; changing it re-hashes and
creates an audit entry.

```toml
[engagement]
id = "eng-juiceshop-001"
client = "OWASP Juice Shop Lab"
start_time = "2026-05-21T09:00:00Z"
end_time   = "2026-05-21T18:00:00Z"

[[targets]]
cidr = "10.10.10.0/24"
description = "Corporate network - staging"
environment = "non-production"

[[targets]]
cidr = "10.10.0.0/24"
description = "External-facing DMZ"
environment = "production"
restrictions = ["recon_only", "no_exploitation"]
```

Then update the Cedar scope policy to match your engagement requirements:

```text
policies/scope.cedar
```

### Build

The first build takes roughly 15 minutes for Rust compilation against a Kali base image.

```bash
docker compose build
```

### Run

The runtime is launched via the container entrypoint. Ports are published with `-p`:

```bash
docker run --rm --network host --privileged \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  -e SYMBIONT_API_TOKEN="$SYMBIONT_API_TOKEN" \
  -e SYMBIONT_MASTER_KEY="$SYMBIONT_MASTER_KEY" \
  symbi-redteam:latest \
  up -p 9080 --http-port 9081 --http.token "your-webhook-token"
```

For live editing of policies, scope, agents, or scripts, add read-only mounts:

```bash
  -v ./policies:/app/policies:ro \
  -v ./scope:/app/scope:ro \
  -v ./agents:/app/agents:ro \
  -v ./scripts:/app/scripts \
  -v ./templates:/app/templates:ro \
```

The default services expose:

| Port    | Purpose                   | Auth                  |
| ------- | ------------------------- | --------------------- |
| `9080`  | Runtime REST API          | `SYMBIONT_API_TOKEN` (Bearer) |
| `9081`  | HTTP input webhook        | `--http.token` (Bearer) |
| `9082`  | Optional Slack approval webhook | Slack signing secret |
| `4317`  | OTLP gRPC collector       | Local deployment only |
| `16686` | Jaeger UI                 | Local deployment only |

### Health check

```bash
curl -s http://localhost:9080/api/v1/health
```

### List agents

```bash
curl -s \
  -H "Authorization: Bearer $SYMBIONT_API_TOKEN" \
  http://localhost:9080/api/v1/agents
```

### Start an engagement

Execute an agent through the REST API. Prefer scoped, structured input over free-form target instructions:

```bash
curl -s -X POST \
  -H "Authorization: Bearer $SYMBIONT_API_TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:9080/api/v1/agents/{agent-id}/execute \
  -d '{"input": "Run the engagement defined in scope/scope.toml"}'
```

Interactive API docs are served at `http://localhost:9080/swagger-ui/`.

---

## Running in lab mode

For development and demos, use intentionally vulnerable lab targets that you own.

Recommended examples:

* OWASP Juice Shop
* DVWA
* Metasploitable
* local containerized test services
* internal capture-the-flag environments

Do not point lab mode at internet targets.

---

## Optional signed validation seed

Some deployments may ingest signed validation objectives from a private upstream analysis pipeline.

Example shape:

```json
{
  "seed_version": "1",
  "producer": "private-analysis-pipeline",
  "engagement_id": "eng_01J...",
  "objectives": [
    {
      "id": "obj_01J...",
      "title": "Validate exposed admin interface",
      "target_hint": "app.internal",
      "evidence_refs": ["ev_01J..."],
      "risk": "medium-high",
      "allowed_validation": ["recon", "enumeration", "non_destructive_check"]
    }
  ],
  "signature": {
    "alg": "Ed25519",
    "key_id": "producer-key-1",
    "sig": "base64..."
  }
}
```

The seed does not grant authority. It proposes validation objectives. Symbiont still evaluates scope, policy, risk, approvals, and time bounds before any action runs.

---

## Human approvals

High-risk and highest-risk actions (exploit, post-exploit) require human approval. Symbiont's HumanCritic suspends the ORGA loop and prompts the operator; approval tokens have a configurable expiry enforced by Cedar.

Approval decisions include:

* requested action
* target
* risk tier
* rationale
* proposed tool
* expected effect
* evidence requirement
* expiry time
* approver identity
* final decision

Example approval record:

```json
{
  "approval_id": "appr_01J...",
  "engagement_id": "eng_01J...",
  "requested_by": "exploit",
  "tool": "metasploit_run",
  "target": "10.10.10.25",
  "risk": "high",
  "decision": "approved",
  "approved_by": "operator@example.com",
  "expires_at": "2026-05-21T16:30:00Z"
}
```

### Slack approval relay

When enabled, human-gated tools post an Approve/Deny prompt to Slack in addition to the CLI prompt. The first responder wins.

**Slack app setup:**
1. Create a Slack app at https://api.slack.com/apps
2. Bot Token Scopes: `chat:write`, `chat:write.public`, `im:write`
3. Interactivity & Shortcuts: enable; Request URL = `https://<your-host>:9082/slack/events`
4. Install to workspace; copy Bot Token (`xoxb-…`) and Signing Secret
5. Invite the bot to the approval channel: `/invite @your-bot #symbi-approvals`

Required environment variables:

```bash
export SLACK_BOT_TOKEN=xoxb-...
export SLACK_SIGNING_SECRET=...
```

Configure `symbi.toml`:

```toml
[approvals.slack]
enabled = true
bot_token_env = "SLACK_BOT_TOKEN"
signing_secret_env = "SLACK_SIGNING_SECRET"
channel = "#symbi-approvals"
approvers = ["U01ABC123", "U02DEF456"]   # Slack member IDs
dm_approvers = true
events_bind_addr = "0.0.0.0:9082"
```

Pending approvals are currently in-memory; on container restart they are lost and the agent re-prompts on retry. For production deployments, back approval state with durable storage. Per-engagement Cedar-mapped approvers and non-Slack channels are deferred.

---

## Audit trail

Every security-relevant operation is written to the Symbiont audit journal at `.symbiont/audit/` as hash-chained JSONL (configured in `symbi.toml`). In Docker these persist to the host via the `audit-logs/` mount.

Events include:

* agent lifecycle changes
* policy evaluations
* tool invocations
* approval requests and decisions
* evidence writes
* finding updates and verifications
* report generation
* denied actions
* rate-limit events
* scope violations

Example:

```json
{
  "event_id": "evt_01J...",
  "previous_hash": "7b9d...",
  "event_hash": "ad31...",
  "timestamp": "2026-05-21T20:11:08Z",
  "agent": "enum",
  "action": "run_tool",
  "tool": "nikto_scan",
  "target": "lab.internal",
  "cedar_decision": "allow",
  "evidence_id": "ev_01J..."
}
```

View audit logs:

```bash
cat audit-logs/*.jsonl | jq .
```

Filter denied actions:

```bash
cat audit-logs/*.jsonl | jq 'select(.cedar_decision == "deny")'
```

Verify integrity:

```bash
symbi audit verify .symbiont/audit/
```

---

## Observability

`symbi-redteam` supports OpenTelemetry tracing through Symbiont. Traces show the full ORGA loop per agent (Observe, Reason, Gate, Act) with cross-agent propagation through `ask()` calls.

Traces can include:

* engagement controller decisions
* ORGA loop phases
* Cedar policy evaluations (permit/deny)
* tool execution duration
* inter-agent `ask()` calls
* approval latency
* evidence writes
* report generation

Start Jaeger locally:

```bash
docker run -d --name jaeger \
  -p 16686:16686 \
  -p 4317:4317 \
  jaegertracing/all-in-one:latest
```

Enable telemetry in `symbi.toml`:

```toml
[telemetry]
enabled = true
otlp_endpoint = "http://localhost:4317"
service_name = "symbi-redteam"
```

Then open `http://localhost:16686` and select the `symbi-redteam` service.

---

## Web viewer

`redteam-web` is a local, **read-only** dashboard over one engagement's SQLite
database — a companion binary built from this crate (server-rendered Rust +
Maud, no JS build step). It has **no authentication**: bind it to localhost and
do not expose it to a network.

```bash
# Build the viewer binary
cargo build --release --bin redteam-web

# Serve the engagement DB (read-only); auto-resolves the sole engagement
./target/release/redteam-web --db data/redteam.db --port 8088

# Then open http://127.0.0.1:8088
```

Flags: `--db` (engagement SQLite, opened read-only), `--engagement <id>` (only
needed when the DB holds more than one), `--port` (default `8088`), `--bind`
(default `127.0.0.1`), `--journal` (hash-chained audit log for the integrity
badge; auto-located next to the DB), `--report` (a `report.md` to render).

Pages:

| Page | Shows |
|---|---|
| Overview | Engagement header, severity histogram, phase breakdown, Cedar allow/deny tallies, audit-integrity badge |
| Findings | Filterable/sortable table (phase, severity, tool) with target, CVSS, and validate status |
| Finding detail | Full finding plus the **validate-agent adjudication trail** (`finding_verifications`: verdict, verifier, rationale) |
| Knowledge | Reflector-authored subject-predicate-object triples |
| Evidence | The `tool_runs` log — command, exit code, Cedar decision/policy, approver |
| Graph | Findings clustered by target host, overlaid with reflector knowledge relations (cytoscape) |
| Report | The reporter agent's `report.md`, rendered (raw HTML neutralised) |

The audit badge verifies hash-chain *linkage* (each entry references the prior
entry's hash); full cryptographic verification stays with `symbi audit verify`.
The viewer is not wired into the Docker image — build and run it on the host
against the persisted `data/` volume.

---

## Repository layout

```text
symbi-redteam/
├── agents/                 # 9 Symbiont agent definitions (.symbi)
├── policies/               # 9 Cedar policy files
├── tools/                  # 19 ToolClad manifests (.clad.toml)
├── toolclad.toml           # project-level custom type definitions
├── scripts/
│   ├── tool-wrappers/      # 19 sandboxed tool wrappers
│   └── parse-outputs/      # output parsers
├── scope/                  # engagement scope (scope.toml)
├── templates/              # report templates
├── src/                    # Rust MCP tool registration + db layer
│   ├── web/                # read-only web viewer (axum + maud)
│   └── bin/web.rs          # redteam-web binary entrypoint
├── assets/                 # web viewer static assets (CSS/JS/fonts)
├── db/                     # SQLite schema + migrations/
├── docs/                   # design docs
├── tests/                  # tests
├── audit-logs/             # local audit output (host mount)
├── evidence/               # local evidence output (host mount)
├── reports/                # generated reports (host mount)
├── scan-results/           # raw scan output (host mount)
├── data/                   # SQLite + LanceDB (host mount)
├── Dockerfile              # Multi-stage: Rust builder + Kali runtime
├── docker-compose.yml      # Security-hardened container config
├── symbi.toml              # Symbiont runtime configuration
└── README.md
```

Legacy databases created before the validate-agent cutover have `verified = FALSE`
for every finding, which now blocks `generate_report`. Backfill once per legacy
database:

```bash
sqlite3 /path/to/redteam.db < db/migrations/2026-05-21-validate-cutover.sql
```

---

## Configuration

### Environment variables

| Variable               | Required                   | Description                          |
| ---------------------- | -------------------------- | ------------------------------------ |
| `ANTHROPIC_API_KEY`    | Yes                        | LLM provider key for reasoning       |
| `SYMBIONT_API_TOKEN`   | Yes                        | Bearer token for the runtime API     |
| `SYMBIONT_MASTER_KEY`  | Yes                        | 256-bit hex key for local encryption |
| `SYMBI_LOG_LEVEL`      | No                         | `debug`, `info`, `warn`, or `error`  |
| `RUST_LOG`             | No                         | Rust tracing filter                  |
| `SLACK_BOT_TOKEN`      | If Slack approvals enabled | Slack bot token                      |
| `SLACK_SIGNING_SECRET` | If Slack approvals enabled | Slack webhook verification secret    |

### Runtime config

The actual `symbi.toml`:

```toml
[runtime]
max_agents = 8                      # controller + 1 phase agent active at a time
memory_limit_mb = 512
execution_timeout_seconds = 1800    # 30 min per phase agent

[security]
default_sandbox_tier = "docker"
audit_enabled = true
policy_enforcement = "strict"       # deny-by-default
allow_native_execution = false

[security.capabilities]
allowed = ["net_raw", "net_admin"]  # SYN scans + tunneling
denied = ["*"]

[policy]
policy_dir = "policies"
default_decision = "deny"
evaluation_timeout_ms = 5

[audit]
enabled = true
output_dir = ".symbiont/audit"
format = "jsonl"
hash_chain = true

[vector_db]
enabled = true
backend = "lancedb"
collection_name = "redteam_embeddings"

[toolclad]
tools_dir = "tools"
custom_types = "toolclad.toml"

[agent]
max_iterations = 15
model = "claude-sonnet-4-6-20260401"
temperature = 0.1

[approvals.slack]
enabled = false
```

---

## Tool contracts

All 19 offensive tools have declarative [ToolClad](https://toolclad.org) manifests in `tools/`. Each `.clad.toml` describes:

* tool name and description
* typed parameters with validation (scope_target, port, enum, credential_file, msf_options, …)
* risk tier and human-approval requirement
* timeout
* evidence requirements (capture stdout/stderr, hash output)
* scope requirements
* generated MCP `inputSchema` / `outputSchema`
* Cedar metadata (resource, action)

Manifests use the executor escape hatch to delegate to the existing shell wrappers, preserving defense-in-depth while adding ToolClad's typed validation layer:

```text
Agent fills typed parameters → ToolClad validates → Shell wrapper executes → Evidence envelope
```

Custom types in `toolclad.toml` define project-specific enums and constraints:
`hydra_service`, `nmap_scan_type`, `severity_level`, `dns_record_type`, `scan_rate`, `msf_module_path`, `impacket_tool`.

```bash
symbi tools validate                 # validate all manifests
symbi tools schema nmap_scan         # generate MCP schema
symbi tools test nmap_scan --arg target=10.0.1.5 --arg scan_type=service
symbi tools list                     # list discovered tools
```

---

## Reporting

Reports should separate evidence from interpretation.

Recommended report sections:

1. Executive summary
2. Engagement scope
3. Methodology
4. Policy and approval summary
5. Validated findings
6. Findings not reproduced
7. Inconclusive objectives
8. Out-of-scope or policy-blocked objectives
9. Evidence index
10. Remediation plan
11. Retest plan
12. Audit summary

Example finding format:

```json
{
  "finding_id": "find_01J...",
  "title": "Exposed administrative interface",
  "severity": "medium",
  "status": "verified",
  "target": "lab.internal",
  "evidence": ["ev_01J...", "ev_01K..."],
  "policy_context": {
    "scope": "allowed",
    "risk_tier": "medium",
    "approval_required": false
  },
  "recommendation": "Restrict administrative interface to trusted networks and require strong authentication."
}
```

---

## Retesting

Retesting reuses the original finding, scope, and evidence context. The
reporter's `compare_engagements` tool takes a current and baseline engagement ID
and produces a delta report.

Retest output should state:

* what changed
* what was retested
* what evidence was collected
* whether the issue is mitigated, still present, or inconclusive
* whether new risk was introduced

Example retest status:

```json
{
  "finding_id": "find_01J...",
  "retest_id": "retest_01K...",
  "status": "mitigated",
  "evidence": ["ev_01K..."],
  "notes": "The administrative interface is no longer reachable from the tested network segment."
}
```

---

## Development

The platform is normally built and run inside Docker (multi-stage Rust builder +
Kali runtime). For local Rust development:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

Run local containers:

```bash
docker compose up --build
```

Tool wrappers can be exercised directly inside the container without the full runtime:

```bash
docker run --rm --network host --privileged --user root \
  --entrypoint bash symbi-redteam:latest -c \
  '/app/scripts/tool-wrappers/nmap-wrapper.sh 10.0.1.5 service "" test-001'
```

---

## Security boundaries

`symbi-redteam` provides governance controls, but deployment still matters.

Recommended production controls:

* run in isolated test networks
* use explicit allowlists
* deny by default
* require approval for high-risk tools
* separate operator and system roles
* retain audit logs outside the container
* export logs to SIEM
* restrict outbound network access
* avoid mounting sensitive host paths
* rotate API tokens and signing keys
* review generated reports before distribution
* test policies before every engagement

Do not rely on prompts as a security boundary.

---

## Known limitations

* Policy examples are starting points and must be adapted for each engagement.
* Human approvals are in-memory and should use durable storage in production.
* Some tools require elevated container capabilities (`NET_RAW`, `NET_ADMIN`) in lab environments.
* Gobuster needs `--exclude-length` for SPA targets that return 200 for all paths; the agent's reasoning handles this.
* Nuclei templates are pre-downloaded during the Docker build; template updates require a rebuild.
* Metasploit first-run initialization takes 30–60 seconds while the framework loads.
* Some scanners produce noisy or ambiguous output.
* LLM-generated plans can be wrong, incomplete, or overconfident.
* A denied action is expected behavior when scope or policy does not permit execution.
* An inconclusive validation is not proof that a finding is false.
* Lab defaults are not production hardening.
* Report output should be reviewed by a qualified security professional.

---

## Responsible use

By using this project, you agree to use it only for:

* systems you own
* systems you are explicitly authorized to test
* lab environments
* internal security validation
* contracted security engagements with written permission

Do not use this project for unauthorized access, credential attacks, persistence, evasion, data theft, or disruption.

---

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

---

## Summary

`symbi-redteam` brings Symbiont's governed execution model to red-team validation.

The goal is not to make offensive agents unconstrained.

The goal is to make security validation faster, more repeatable, more evidence-backed, and safer to operate in environments where scope, approval, and audit matter.

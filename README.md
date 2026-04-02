# symbi-redteam

<p align="center">
  <img src="symbi-redteam.png" alt="symbi-redteam" width="300">
</p>

Governed autonomous penetration testing platform powered by [Symbiont](https://github.com/ThirdKeyAI/symbiont). An AI engagement controller orchestrates a multi-phase pen test across a curated offensive toolchain where every tool has a different risk profile, every action is Cedar policy-gated, and every finding is evidence-chained.

## The Problem

Penetration testing firms face four persistent problems:

1. **Scope creep** — testers accidentally hit out-of-scope assets
2. **Evidence chain integrity** — tampering risk in findings
3. **Junior tester supervision** — unsupervised high-risk tool usage
4. **Reporting overhead** — 40% of engagement time writing reports

## The Solution: ORGA-Governed Multi-Agent Pen Testing

Seven specialized agents execute a PTES-methodology pen test. Every tool invocation passes through Symbiont's ORGA (Observe-Reason-Gate-Act) loop with Cedar policy enforcement:

```
engagement-controller
├── recon agent         → nmap, whois, dig, whatweb, amass
├── enum agent          → nikto, gobuster, enum4linux, smbclient, snmpwalk
├── vuln-assess agent   → nmap NSE, nuclei, sqlmap (detect), searchsploit
├── exploit agent       → hydra, metasploit, sqlmap (exploit)  [human-gated]
├── post-exploit agent  → impacket, pypykatz, chisel, ligolo   [human-gated]
└── reporter agent      → executive, technical, remediation reports
```

**The critical insight:** The Gate operates outside LLM influence. An AI plans Metasploit usage; a human approves each exploitation attempt. Cedar policies cannot be bypassed through prompt injection, social engineering, or creative reasoning.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Engagement Controller                  │
│    Maintains state · Enforces methodology · Orchestrates│
└───────┬───────┬───────┬───────┬───────┬───────┬─────────┘
        │       │       │       │       │       │
   ┌────▼──┐ ┌─▼───┐ ┌─▼───┐ ┌▼────┐ ┌▼────┐ ┌▼────────┐
   │ Recon │ │Enum │ │Vuln │ │Expl.│ │Post │ │Reporter │
   │       │ │     │ │     │ │     │ │Expl.│ │         │
   └───┬───┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └────┬────┘
       │        │       │       │       │          │
   ┌───▼────────▼───────▼───────▼───────▼──────────▼─────┐
   │          ToolClad Manifests (19 .clad.toml)         │
   │  Typed args · MCP schema · Evidence · Cedar metadata │
   ├─────────────────────────────────────────────────────┤
   │              MCP Tool Layer (31 tools)              │
   │  Rust implementations · Cedar-gated · Audit-logged  │
   ├─────────────────────────────────────────────────────┤
   │              Shell Wrappers (19 scripts)            │
   │  Arg validation · Timeout · JSON output · Defense   │
   ├─────────────────────────────────────────────────────┤
   │            Offensive Toolchain (Kali)               │
   │  nmap · nikto · nuclei · sqlmap · hydra · metasploit│
   │  impacket · pypykatz · chisel · ligolo · gobuster   │
   └─────────────────────────────────────────────────────┘
```

## Risk-Tiered Tool Authorization

| Risk Level | Tools | Authorization |
|------------|-------|---------------|
| Low | nmap, whois, dig, whatweb, amass | Auto-allowed within scope |
| Medium | nikto, gobuster, enum4linux, smbclient, snmpwalk | Rate-limited |
| Medium-High | nmap NSE, nuclei, sqlmap (detect), searchsploit | Non-production only |
| High | hydra, metasploit, sqlmap (exploit) | Human approval required |
| Highest | impacket, pypykatz, chisel, ligolo | Human approval + scope revalidation |

## Cedar Policy Model

Seven policy files enforce governance at every level:

| Policy | Purpose |
|--------|---------|
| `scope.cedar` | Target CIDR enforcement, excluded assets |
| `tool-authorization.cedar` | Per-tool risk-tiered authorization |
| `phase-gates.cedar` | PTES methodology enforcement |
| `rate-limits.cedar` | Per-target and global frequency limits |
| `escalation.cedar` | Human approval with time-limited expiry |
| `evidence.cedar` | Evidence chain integrity requirements |
| `time-bounds.cedar` | Engagement window enforcement |

## Data Layer

**SQLite** stores structured engagement data: findings, tool runs, retests.

**LanceDB** provides semantic search across findings for cross-tool correlation and retest comparison. A service that moved from port 8080 to 8443 still gets matched. A finding described differently by a different scanner still gets correlated.

**Evidence store** archives all tool outputs with SHA-256 integrity hashing, creating a tamper-evident chain from discovery through reporting.

## Quick Start

### Prerequisites

- Docker
- An Anthropic API key

### Using the pre-built image

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/thirdkeyai/symbi-redteam:latest

# Set required environment variables
export ANTHROPIC_API_KEY=your-key
export SYMBIONT_MASTER_KEY=$(openssl rand -hex 32)

# Start the runtime
docker run --rm --network host --privileged \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  -e SYMBIONT_API_TOKEN="your-api-token" \
  -e SYMBIONT_MASTER_KEY="$SYMBIONT_MASTER_KEY" \
  ghcr.io/thirdkeyai/symbi-redteam:latest \
  up -p 9080 --http-port 9081 --http.token "your-webhook-token"
```

### Building from source

To build locally (e.g., to customize agents, policies, or tools):

```bash
# Clone the repo
git clone https://github.com/ThirdKeyAI/symbi-redteam.git
cd symbi-redteam

# Build the container (first build ~15 min for Rust compilation)
docker compose build

# Start with local mounts for live editing
docker run --rm --network host --privileged \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  -e SYMBIONT_API_TOKEN="your-api-token" \
  -e SYMBIONT_MASTER_KEY="$SYMBIONT_MASTER_KEY" \
  -v ./policies:/app/policies:ro \
  -v ./scope:/app/scope:ro \
  -v ./agents:/app/agents:ro \
  -v ./scripts:/app/scripts \
  -v ./templates:/app/templates:ro \
  symbi-redteam:latest \
  up -p 9080 --http-port 9081 --http.token "your-webhook-token"
```

### Interact via API

```bash
# Health check
curl -s http://localhost:9080/api/v1/health

# List loaded agents (7 agents from agents/ directory)
curl -s -H "Authorization: Bearer your-api-token" \
  http://localhost:9080/api/v1/agents

# Execute an agent
curl -s -X POST -H "Authorization: Bearer your-api-token" \
  -H "Content-Type: application/json" \
  http://localhost:9080/api/v1/agents/{agent-id}/execute \
  -d '{"input": "Scan 10.0.1.0/24 for open services"}'

# Swagger API docs
open http://localhost:9080/swagger-ui/
```

### Test individual tools

Tool wrappers can be tested directly inside the container without the full runtime:

```bash
docker run --rm --network host --privileged --user root \
  --entrypoint bash symbi-redteam:latest -c \
  '/app/scripts/tool-wrappers/nmap-wrapper.sh 10.0.1.5 service "" test-001'
```

### Configure scope

Edit `scope/scope.toml` to define your engagement targets and update `policies/scope.cedar` to match. The scope is baked into Cedar policies for this demo.

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes | API key for LLM reasoning |
| `SYMBIONT_API_TOKEN` | Yes | Bearer token for the runtime REST API (port 9080) |
| `SYMBIONT_MASTER_KEY` | Yes | 256-bit hex key for encryption (`openssl rand -hex 32`) |
| `SYMBI_LOG_LEVEL` | No | Log level: debug, info, warn, error (default: info) |

### Ports

| Port | Purpose | Authentication |
|------|---------|----------------|
| 9080 | Runtime REST API (agents, status, execute) | `SYMBIONT_API_TOKEN` via Bearer header |
| 9081 | HTTP Input webhook (agent invocation) | `--http.token` via Bearer header |
| 4317 | OTLP gRPC (Jaeger trace collector) | None (local only) |
| 16686 | Jaeger UI | None (local only) |

### Observability

#### Audit trail

Every tool invocation is logged to `.symbiont/audit/` as JSONL with SHA-256 hash chaining (configured in `symbi.toml`). In Docker, these are persisted to the host via the `audit-logs/` volume mount:

```bash
# View recent audit entries
cat audit-logs/*.jsonl | jq .

# Filter by tool name
cat audit-logs/*.jsonl | jq 'select(.tool == "nmap_scan")'

# Filter by Cedar decision
cat audit-logs/*.jsonl | jq 'select(.cedar_decision == "deny")'
```

#### Distributed tracing with Jaeger

Symbiont 1.9.0+ supports W3C traceparent propagation via OpenTelemetry. Traces show the full ORGA loop per agent (Observe, Reason, Gate, Act) with cross-agent propagation through `ask()` calls.

**1. Start Jaeger:**

```bash
docker run -d --name jaeger \
  -p 16686:16686 \
  -p 4317:4317 \
  jaegertracing/all-in-one:latest
```

**2. Add telemetry config to `symbi.toml`:**

```toml
[telemetry]
enabled = true
otlp_endpoint = "http://localhost:4317"
```

**3. View traces:**

Open `http://localhost:16686` and select the `symbi-redteam` service. Each engagement run produces traces spanning all phase agents, with spans for:

- Agent ORGA loop iterations
- Cedar policy evaluations (permit/deny)
- Tool executions (wrapper invocation + duration)
- Inter-agent `ask()` calls (controller → phase agent)
- Human approval gates (time-to-approve)

#### Log verbosity

```bash
# Increase log detail for debugging
SYMBI_LOG_LEVEL=debug RUST_LOG=symbi=debug,cedar=info
```

### Known limitations

- **Gobuster** requires `--exclude-length` for SPA targets (like Juice Shop) that return 200 for all paths. The agent's reasoning phase handles this automatically.
- **Nuclei** downloads templates on first run inside the container. Templates are pre-downloaded during Docker build, but template updates require a rebuild.
- **Metasploit** first-run initialization takes 30-60 seconds while the framework loads.
- **Non-root execution**: The container runs as the `symbi` user by default. Tools requiring raw sockets (nmap SYN scans, chisel tunneling) need `--cap-add NET_RAW --cap-add NET_ADMIN` or `--privileged` for testing.
- **MCP tool registration**: ToolClad manifests in `tools/` auto-generate MCP schemas via `toolclad schema`. The Rust MCP tool definitions in `src/` provide the runtime registration layer. The Symbiont runtime's ToolCladExecutor discovers manifests from `tools/` and registers them as MCP tools automatically.

## Repository Structure

```
symbi-redteam/
├── agents/                    # 7 Symbiont DSL agent definitions
│   ├── engagement-controller.dsl  # Orchestrator
│   ├── recon.dsl                  # Reconnaissance
│   ├── enum.dsl                   # Enumeration
│   ├── vuln-assess.dsl            # Vulnerability assessment
│   ├── exploit.dsl                # Exploitation (human-gated)
│   ├── post-exploit.dsl           # Post-exploitation (human-gated)
│   └── reporter.dsl              # Report generation
├── tools/                     # 19 ToolClad manifests (.clad.toml)
├── toolclad.toml              # Project-level custom type definitions
├── policies/                  # 7 Cedar policy files
├── src/                       # Rust MCP tool definitions
│   ├── recon_tools.rs            # 5 recon tools + parse + CVE lookup
│   ├── enum_tools.rs             # 5 enumeration tools
│   ├── vuln_tools.rs             # 4 vulnerability tools
│   ├── exploit_tools.rs          # 4 exploitation tools
│   ├── postexploit_tools.rs      # 4 post-exploitation tools
│   ├── evidence_tools.rs         # 5 evidence management tools
│   ├── reporting.rs              # 4 reporting tools
│   └── db.rs                     # SQLite + LanceDB layer
├── scripts/
│   ├── tool-wrappers/            # 19 sandboxed tool wrappers
│   └── parse-outputs/            # 9 output parsers
├── scope/                     # Engagement scope definition
├── db/                        # Database schema
├── templates/                 # Report templates
├── Dockerfile                 # Multi-stage: Rust builder + Kali runtime
├── docker-compose.yml         # Security-hardened container config
└── symbi.toml                 # Symbiont runtime configuration
```

## ToolClad Integration

All 19 offensive tools have declarative [ToolClad](https://toolclad.org) manifests in `tools/`. Each `.clad.toml` defines:

- **Typed parameters** with validation (scope_target, port, enum, credential_file, msf_options, etc.)
- **Cedar metadata** for policy evaluation (resource, action, risk_tier, human_approval)
- **MCP schema generation** — auto-generate `inputSchema`/`outputSchema` from manifests
- **Evidence envelopes** with SHA-256 hashing and structured output

Manifests use the **executor escape hatch** to delegate to existing shell wrappers, preserving defense-in-depth while adding ToolClad's typed validation layer:

```
Agent fills typed parameters → ToolClad validates → Shell wrapper executes → Evidence envelope
```

**Custom types** in `toolclad.toml` define project-specific enums and constraints:
`hydra_service`, `nmap_scan_type`, `severity_level`, `dns_record_type`, `scan_rate`, `msf_module_path`, `impacket_tool`

```bash
# Validate all tool manifests (symbi tools CLI, v1.9.0+)
symbi tools validate

# Generate MCP schema for a tool
symbi tools schema nmap_scan

# Dry-run a tool
symbi tools test nmap_scan --arg target=10.0.1.5 --arg scan_type=service

# List all discovered tools
symbi tools list
```

## Key Design Decisions

**Kali base image** — Provides the offensive toolchain via apt. Larger image but vastly simpler tool installation and dependency management than building from source.

**Hierarchical multi-agent** — The engagement controller delegates to phase agents via `ask()`. Only 2 agents are active concurrently (controller + current phase). This maps naturally to PTES methodology and keeps Cedar policies scoped per phase.

**Cedar over inline checks** — Cedar policies are formally verifiable, updatable without code changes, and evaluated outside LLM influence. The Gate cannot be prompt-injected.

**SQLite + LanceDB** — Structured data in SQLite for queries, embeddings in LanceDB for semantic search. Single LanceDB collection with type discriminator avoids runtime changes.

**Human approval via CLI** — Symbiont's HumanCritic suspends the ORGA loop and prompts the operator. Approval tokens have configurable expiry (30-60 minutes) enforced by Cedar.

## Comparison

| Capability | Raw Tools | symbi-redteam |
|------------|-----------|---------------|
| Scope enforcement | Manual discipline | Cedar policy — automatic |
| Phase methodology | Tester judgment | Policy-gated transitions |
| Tool authorization | Honor system | Risk-tiered Cedar policies |
| Rate limiting | Manual | Automatic per-target + global |
| Human approval | Verbal/email | CLI prompt with timed expiry |
| Evidence integrity | Trust-based | SHA-256 hash chains |
| Audit trail | Manual notes | Cryptographic, tamper-evident |
| Report generation | 40% of engagement time | Automated from evidence DB |
| Retest comparison | Manual analyst work | Semantic matching + delta reports |

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

# symbi-redteam

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
│                  Engagement Controller                    │
│    Maintains state · Enforces methodology · Orchestrates │
└───────┬───────┬───────┬───────┬───────┬───────┬─────────┘
        │       │       │       │       │       │
   ┌────▼──┐ ┌─▼───┐ ┌─▼───┐ ┌▼────┐ ┌▼────┐ ┌▼────────┐
   │ Recon │ │Enum │ │Vuln │ │Expl.│ │Post │ │Reporter │
   │       │ │     │ │     │ │     │ │Expl.│ │         │
   └───┬───┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └────┬────┘
       │        │       │       │       │          │
   ┌───▼────────▼───────▼───────▼───────▼──────────▼─────┐
   │              MCP Tool Layer (31 tools)                │
   │  Rust implementations · Cedar-gated · Audit-logged   │
   ├──────────────────────────────────────────────────────┤
   │              Shell Wrappers (19 scripts)              │
   │  Arg validation · Timeout · JSON output · Defense     │
   ├──────────────────────────────────────────────────────┤
   │            Offensive Toolchain (Kali)                 │
   │  nmap · nikto · nuclei · sqlmap · hydra · metasploit │
   │  impacket · pypykatz · chisel · ligolo · gobuster    │
   └──────────────────────────────────────────────────────┘
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

```bash
# Set your API key
export ANTHROPIC_API_KEY=your-key

# Build the container
docker compose build

# Start the governed pen test platform
docker compose up

# The engagement controller will:
# 1. Initialize the engagement
# 2. Run recon → enum → vuln → exploit → post-exploit → report
# 3. Generate executive, technical, and remediation reports
# 4. All in markdown, HTML, and PDF formats
```

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

MIT — see [LICENSE](LICENSE) for details.

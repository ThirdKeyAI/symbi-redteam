# AGENTS.md -- AI Agent Instructions for symbi-redteam

## Project Overview

This repository is a governed autonomous penetration testing platform using the Symbiont trust stack. Eight hierarchical agents (six phase agents, one orchestrator, one reflector) run a PTES-methodology pen test with Cedar policy enforcement, risk-tiered tool authorization, and cryptographic audit trails. Between phases a bounded reflector agent distils lessons into a knowledge store the next phase reads — a pattern borrowed from `symbiont-karpathy-loop`.

## Architecture

The system has five layers:

1. **Offensive toolchain** (Kali): nmap, nikto, nuclei, sqlmap, hydra, metasploit, impacket, pypykatz, chisel, ligolo, gobuster, enum4linux, smbclient, snmpwalk, amass, whatweb, whois, searchsploit. Dumb tools with no concept of governance.
2. **Wrapper scripts** (`scripts/tool-wrappers/`): 19 sandboxed wrappers. Sanitize arguments, capture output, enforce timeouts, return structured JSON. Defense in depth.
3. **MCP tools** (`src/*.rs`): 33 Rust-defined tools across 8 modules. Each tool call is intercepted by the ORGA Gate for Cedar policy evaluation.
4. **Agent DSL** (`agents/`): 8 Symbiont DSL agents in a hierarchical tree. The engagement controller orchestrates 6 phase agents via `ask()`, and invokes the bounded reflector after each phase.
5. **Symbiont runtime**: Runs ORGA loops, evaluates Cedar policies, manages inter-agent communication, maintains cryptographic audit trail.

## Agent Hierarchy

```
engagement-controller.dsl
├── ask(recon)          — Low risk, auto-allowed
├── ask(reflector)      — Post-phase; store_knowledge only
├── ask(enum)           — Medium risk, rate-limited
├── ask(reflector)      — Post-phase; store_knowledge only
├── ask(vuln-assess)    — Medium-high risk, non-prod only
├── ask(reflector)      — Post-phase; store_knowledge only
├── ask(exploit)        — High risk, human approval required
├── ask(reflector)      — Post-phase; store_knowledge only
├── ask(post-exploit)   — Highest risk, approval + scope revalidation
├── ask(reflector)      — Post-phase; store_knowledge only
└── ask(reporter)       — Report generation, always allowed
```

The reflector pattern (borrowed from `symbiont-karpathy-loop`) runs after
each phase. It reads the phase's findings and writes subject-predicate-object
lessons to the `knowledge` table. The next phase's agent pulls those lessons
via `recall_knowledge` before planning. Cedar's `reflector.cedar` bounds the
reflector with a defensive `forbid unless` so it can only call
`store_knowledge`, `recall_knowledge`, and `query_findings` — every scan,
enum, exploit, and post-exploit tool is rejected at the gate.

## Key Files

| File | Purpose | When to modify |
|---|---|---|
| `agents/engagement-controller.dsl` | Orchestrator agent | Changing phase ordering, adding new phases |
| `agents/recon.dsl` | Reconnaissance | Adding recon tools, changing scan strategy |
| `agents/enum.dsl` | Enumeration | Adding enum tools, changing enumeration targets |
| `agents/vuln-assess.dsl` | Vulnerability assessment | Changing vuln scan templates or strategies |
| `agents/exploit.dsl` | Exploitation | Changing exploit selection or approval workflow |
| `agents/post-exploit.dsl` | Post-exploitation | Changing lateral movement strategies |
| `agents/reporter.dsl` | Report generation | Changing report types or formats |
| `agents/reflector.dsl` | Post-phase lesson extractor | Changing reflector prompt or triple shape |
| `policies/scope.cedar` | Target scope | Adding/removing allowed CIDRs |
| `policies/tool-authorization.cedar` | Tool risk tiers | Changing which tools need which authorization |
| `policies/phase-gates.cedar` | Phase transitions | Changing methodology requirements |
| `policies/rate-limits.cedar` | Frequency limits | Adjusting per-target and global limits |
| `policies/escalation.cedar` | Human approval | Changing approval expiry or requirements |
| `policies/evidence.cedar` | Evidence rules | Changing evidence chain requirements |
| `policies/reflector.cedar` | Reflector bounds | Changing what tools the reflector can call |
| `policies/time-bounds.cedar` | Engagement window | Changing time restrictions |
| `src/recon_tools.rs` | 7 recon MCP tools | Adding recon tools or changing schemas |
| `src/enum_tools.rs` | 5 enum MCP tools | Adding enum tools |
| `src/vuln_tools.rs` | 4 vuln MCP tools | Adding vuln tools |
| `src/exploit_tools.rs` | 4 exploit MCP tools | Adding exploit tools |
| `src/postexploit_tools.rs` | 4 post-exploit MCP tools | Adding post-exploit tools |
| `src/evidence_tools.rs` | 5 evidence MCP tools | Changing evidence storage |
| `src/knowledge_tools.rs` | 2 knowledge MCP tools | Changing reflector/recall contract |
| `src/reporting.rs` | 4 reporting MCP tools | Changing report generation |
| `src/db.rs` | Database layer | Schema changes, new queries |
| `scope/scope.toml` | Engagement scope | Changing target definitions |
| `db/schema.sql` | SQLite schema | Adding tables or indexes |
| `templates/report-*.md` | Report templates | Changing report layout |

## Development Rules

1. **Never bypass the Gate.** If a tool needs to execute without policy checks, use `.no_policy_gate()` in tool registration and document why.
2. **Capabilities are explicit.** If an agent needs a new capability, add it to the DSL `capabilities` list and the relevant Cedar policies.
3. **Defense in depth.** Wrapper scripts validate arguments even though Cedar already authorized the operation.
4. **Cedar policies are the source of truth.** DSL `policy` blocks are hints; the `.cedar` files in `policies/` are what the runtime evaluates.
5. **Evidence chain integrity.** Every tool run must be recorded via `store_tool_run` before the next tool can execute.
6. **Human approval is non-negotiable.** Exploit and post-exploit tools always require human approval. No exceptions, no overrides.
7. **Test policy changes with `symbi policy evaluate`.** Never deploy Cedar changes without running the policy simulator.

## Common Tasks

### Add a new allowed scan target
Edit `scope/scope.toml` to add the target definition, then update `policies/scope.cedar` with a matching permit rule.

### Add a new tool to an existing phase
1. Add a wrapper script in `scripts/tool-wrappers/`
2. Define input/output structs in the appropriate `src/*_tools.rs`
3. Implement the tool function
4. Register in `register_tools()` with Cedar resource/action mappings
5. Add the capability to the relevant agent DSL file
6. Add Cedar policies in `policies/tool-authorization.cedar`
7. Add a parser in `scripts/parse-outputs/` if the tool has complex output

### Add a new engagement phase
1. Create a new agent DSL file in `agents/`
2. Create a new `src/*_tools.rs` module
3. Add phase-gate rules in `policies/phase-gates.cedar`
4. Add tool authorization rules in `policies/tool-authorization.cedar`
5. Update `engagement-controller.dsl` to orchestrate the new phase
6. Update `symbi.toml` if the new phase needs different resource limits

### Generate a retest comparison
The reporter agent's `compare_engagements` tool takes a current and baseline engagement ID and produces a delta report showing remediated, persistent, regressed, and new findings.

## Registered Tools (33 total)

### Recon Tools (7)
| Tool | Wrapper | Cedar Resource |
|---|---|---|
| `nmap_scan` | `nmap-wrapper.sh` | `PenTest::ScanTarget` |
| `whois_lookup` | `whois-wrapper.sh` | `PenTest::ScanTarget` |
| `dns_enumerate` | `dns-wrapper.sh` | `PenTest::ScanTarget` |
| `whatweb_scan` | `whatweb-wrapper.sh` | `PenTest::ScanTarget` |
| `amass_enum` | `amass-wrapper.sh` | `PenTest::ScanTarget` |
| `parse_nmap_xml` | `parse-nmap-xml.py` | (no gate) |
| `lookup_cve` | NVD API | `PenTest::CveQuery` |

### Enum Tools (5)
| Tool | Wrapper | Cedar Resource |
|---|---|---|
| `nikto_scan` | `nikto-wrapper.sh` | `PenTest::ScanTarget` |
| `gobuster_scan` | `gobuster-wrapper.sh` | `PenTest::ScanTarget` |
| `enum4linux_scan` | `enum4linux-wrapper.sh` | `PenTest::ScanTarget` |
| `smbclient_access` | `smbclient-wrapper.sh` | `PenTest::ScanTarget` |
| `snmpwalk_enum` | `snmpwalk-wrapper.sh` | `PenTest::ScanTarget` |

### Vuln Tools (4)
| Tool | Wrapper | Cedar Resource |
|---|---|---|
| `nmap_vuln_script` | `nmap-wrapper.sh` | `PenTest::ScanTarget` |
| `nuclei_scan` | `nuclei-wrapper.sh` | `PenTest::ScanTarget` |
| `sqlmap_detect` | `sqlmap-wrapper.sh` | `PenTest::ScanTarget` |
| `searchsploit_query` | `searchsploit-wrapper.sh` | (no gate) |

### Exploit Tools (4)
| Tool | Wrapper | Cedar Resource |
|---|---|---|
| `hydra_bruteforce` | `hydra-wrapper.sh` | `PenTest::ScanTarget` |
| `metasploit_run` | `msf-wrapper.sh` | `PenTest::ScanTarget` |
| `sqlmap_exploit` | `sqlmap-wrapper.sh` | `PenTest::ScanTarget` |
| `sqlmap_dump` | `sqlmap-wrapper.sh` | `PenTest::ScanTarget` |

### Post-Exploit Tools (4)
| Tool | Wrapper | Cedar Resource |
|---|---|---|
| `impacket_exec` | `impacket-wrapper.sh` | `PenTest::ScanTarget` |
| `pypykatz_dump` | `pypykatz-wrapper.sh` | `PenTest::ScanTarget` |
| `chisel_tunnel` | `chisel-wrapper.sh` | `PenTest::ScanTarget` |
| `ligolo_proxy` | `ligolo-wrapper.sh` | `PenTest::ScanTarget` |

### Evidence Tools (5)
| Tool | Cedar Resource |
|---|---|
| `store_finding` | `PenTest::EvidenceStore` |
| `query_findings` | `PenTest::EvidenceStore` |
| `search_similar_findings` | `PenTest::EvidenceStore` |
| `store_tool_run` | `PenTest::EvidenceStore` |
| `capture_evidence` | `PenTest::EvidenceStore` |

### Reporting Tools (4)
| Tool | Cedar Resource |
|---|---|
| `generate_report` | `PenTest::ReportGenerator` |
| `compare_engagements` | `PenTest::ReportGenerator` |
| `create_engagement` | `PenTest::EvidenceStore` |
| `manage_engagement` | `PenTest::EvidenceStore` |

### Knowledge Tools (2)
| Tool | Cedar Resource | Who may call it |
|---|---|---|
| `store_knowledge` | `PenTest::KnowledgeStore` | reflector only (enforced by `reflector.cedar`) |
| `recall_knowledge` | `PenTest::KnowledgeStore` | every phase agent (read-only) |

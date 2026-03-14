# symbi-example-nmap

**Adding secured intelligence to dumb tools with Symbiont.**

This example wraps [nmap](https://nmap.org) -- a powerful but unintelligent network scanner -- with a Symbiont agent that adds AI reasoning, policy governance, and cryptographic audit trails. The agent decides *what* to scan, *interprets* results, and *recommends* remediation -- all inside an ORGA-enforced security perimeter that prevents dangerous or unauthorized scans.

## The Problem

nmap is a blunt instrument. It does exactly what you tell it -- including aggressive OS fingerprinting against production servers, full-port SYN floods against hosts you don't own, or UDP scans that trigger IDS alerts. There is no built-in concept of:

- **Authorization**: Is this scan permitted by policy?
- **Proportionality**: Is this scan type appropriate for the target?
- **Interpretation**: What do these results actually mean?
- **Audit**: Who requested this scan, when, and what happened?

## The Solution: ORGA-Governed Intelligence

Symbiont's ORGA loop (Observe-Reason-Gate-Act) wraps nmap with a governed AI agent:

```
User Request: "Check if our staging servers are exposed"
         |
         v
  ┌─────────────────────────────────────────────────────┐
  │  OBSERVE                                            │
  │  - Parse the request                                │
  │  - Load target context (allowed CIDRs, scan history)│
  │  - Check current scan state                         │
  └──────────────────────┬──────────────────────────────┘
                         v
  ┌─────────────────────────────────────────────────────┐
  │  REASON (LLM)                                       │
  │  - Determine appropriate scan type (SYN, service,   │
  │    version detection, etc.)                         │
  │  - Select targets from allowed ranges               │
  │  - Propose nmap command with flags                  │
  └──────────────────────┬──────────────────────────────┘
                         v
  ┌─────────────────────────────────────────────────────┐
  │  GATE (outside LLM influence -- cannot be bypassed) │
  │  - Cedar policy: Is this CIDR in allowed ranges?    │
  │  - Cedar policy: Is this scan type permitted?       │
  │  - Cedar policy: Rate limit (max scans/hour)?       │
  │  - Cedar policy: No aggressive scans without        │
  │    explicit approval?                               │
  │  - DENY or ALLOW                                    │
  └──────────────────────┬──────────────────────────────┘
                         v
  ┌─────────────────────────────────────────────────────┐
  │  ACT                                                │
  │  - Execute approved nmap command in sandbox         │
  │  - Parse XML output                                 │
  │  - Return to OBSERVE for interpretation loop        │
  └─────────────────────────────────────────────────────┘
         |
         v
  ┌─────────────────────────────────────────────────────┐
  │  REASON (interpretation pass)                       │
  │  - Analyze open ports, services, vulnerabilities    │
  │  - Cross-reference with known CVEs                  │
  │  - Generate prioritized remediation report          │
  └─────────────────────────────────────────────────────┘
         |
         v
  Structured Report + Cryptographic Audit Entry
```

The critical insight: **the Gate phase operates outside LLM influence**. The AI cannot talk its way past the policy engine. Even if a prompt injection attempts to convince the LLM to scan unauthorized targets, the Cedar policy evaluation denies the action at the Gate -- and the denial is logged to a tamper-evident audit trail.

## Repository Structure

```
symbi-nmap-agent/
├── README.md                    # This file
├── Dockerfile                   # Container: nmap + symbi runtime
├── docker-compose.yml           # Run with resource limits
├── symbi.toml                   # Runtime configuration
├── agents/
│   └── nmap-recon.dsl           # Agent definition (Symbiont DSL)
├── policies/
│   ├── scan-authorization.cedar # What targets and scan types are allowed
│   ├── rate-limits.cedar        # Scan frequency limits
│   └── escalation.cedar         # When to require human approval
├── scripts/
│   ├── nmap-wrapper.sh          # Sandboxed nmap execution wrapper
│   └── parse-nmap-xml.py        # XML output parser
└── src/
    └── tools.rs                 # MCP tool definitions for nmap operations
```

## Quick Start

```bash
# Build the container
docker build -t symbi-nmap-agent .

# Run a governed scan
docker run --rm \
  -e SYMBI_LOG_LEVEL=info \
  -v $(pwd)/policies:/app/policies:ro \
  symbi-nmap-agent \
  symbi run nmap-recon --prompt "Scan staging subnet for exposed services"

# Or with docker-compose (recommended -- includes resource limits)
docker-compose run --rm agent \
  symbi run nmap-recon --prompt "Check 10.0.1.0/24 for open web ports"
```

## What Makes This Different from Just Running nmap

| Capability | Raw nmap | symbi-nmap-agent |
|---|---|---|
| Target authorization | None | Cedar policy enforcement |
| Scan type governance | None | Policy-gated by risk level |
| Rate limiting | None | Configurable per-target limits |
| Result interpretation | Raw output | AI-generated analysis + CVE correlation |
| Remediation guidance | None | Prioritized recommendations |
| Audit trail | Manual logging | Cryptographic, tamper-evident, automatic |
| Prompt injection defense | N/A | Gate operates outside LLM influence |
| Human approval escalation | N/A | Policy-triggered for aggressive scans |

## Key Design Decisions

**Why Docker (Tier 1) sandbox?** nmap needs raw socket access for SYN scans, which means it needs `CAP_NET_RAW`. We grant this single capability inside the container while dropping everything else. gVisor (Tier 2) would intercept the raw socket syscalls and break nmap's core functionality. Docker with explicit capability management is the right tier here.

**Why Cedar over inline policy checks?** Cedar policies are formally verifiable and can be updated without redeploying the agent. An operator can tighten scan authorization (e.g., remove a subnet during a maintenance window) by editing a `.cedar` file -- no code changes, no container rebuild.

**Why two ORGA passes?** The first pass (scan execution) and second pass (result interpretation) are separate reasoning cycles. This lets the Gate enforce different policies on each: the scan pass checks target authorization, while the interpretation pass can check data classification policies before the report is emitted.

## License

MIT

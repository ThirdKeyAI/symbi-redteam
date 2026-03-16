# =============================================================================
# symbi-redteam
# Governed AI-driven penetration testing platform
#
# This container packages:
#   1. Offensive toolchain    -- nmap, nikto, nuclei, sqlmap, hydra,
#                                metasploit, impacket, pypykatz, chisel, ligolo
#   2. Symbi runtime          -- ORGA governance, Cedar policies, audit trails
#   3. Agent DSL definitions  -- 7 hierarchical agents
#   4. Cedar policies         -- 7 risk-tiered policy files
#   5. Evidence database      -- SQLite + LanceDB
#   6. Report generation      -- pandoc + wkhtmltopdf
#
# Architecture: engagement controller orchestrates 6 phase agents via
# Symbiont's inter-agent communication bus. Every tool invocation is
# Cedar policy-gated and cryptographically audited.
# =============================================================================

# --- Stage 1: Build the symbi runtime ---
FROM rust:1.82-bookworm AS builder

WORKDIR /build

# Install symbi with required features
RUN cargo install symbi \
    --features "cedar,vector-lancedb,cloud-llm,embedding-models" \
    --locked

# --- Stage 2: Runtime image with Kali toolchain ---
FROM kalilinux/kali-rolling

# Prevent interactive prompts during install
ENV DEBIAN_FRONTEND=noninteractive

# Install the full offensive toolchain organized by phase
RUN apt-get update && apt-get install -y --no-install-recommends \
    # --- Recon tools ---
    nmap \
    whois \
    dnsutils \
    whatweb \
    amass \
    # --- Enumeration tools ---
    nikto \
    gobuster \
    enum4linux \
    smbclient \
    snmp \
    # --- Vulnerability assessment ---
    nuclei \
    sqlmap \
    exploitdb \
    # --- Exploitation ---
    hydra \
    metasploit-framework \
    # --- Post-exploitation ---
    impacket-scripts \
    python3-pypykatz \
    chisel \
    ligolo-ng \
    # --- Reporting ---
    pandoc \
    wkhtmltopdf \
    # --- Support ---
    python3 \
    python3-lxml \
    python3-pip \
    ca-certificates \
    jq \
    curl \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Copy symbi binary from builder
COPY --from=builder /usr/local/cargo/bin/symbi /usr/local/bin/symbi

# Create non-root user for the runtime
RUN groupadd -r symbi && useradd -r -g symbi -d /app -s /bin/bash symbi

WORKDIR /app

# Copy application files
COPY agents/ ./agents/
COPY policies/ ./policies/
COPY scripts/ ./scripts/
COPY src/ ./src/
COPY scope/ ./scope/
COPY db/ ./db/
COPY templates/ ./templates/
COPY symbi.toml ./symbi.toml
COPY Cargo.toml ./Cargo.toml

# Make all scripts executable
RUN chmod +x scripts/tool-wrappers/*.sh scripts/parse-outputs/*.py scripts/evidence-capture.sh

# Create directories for runtime state
RUN mkdir -p \
    /app/.symbiont/audit \
    /app/.symbiont/scans \
    /app/.symbiont/reports \
    /app/.symbiont/data \
    /app/.symbiont/data/lance \
    /app/.symbiont/evidence \
    && chown -R symbi:symbi /app

# Drop to non-root (tool capabilities handled at container level)
USER symbi

# Health check: verify symbi and key tools are functional
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD symbi --version && nmap --version && msfconsole --version 2>/dev/null || exit 1

# Default: start the symbi MCP server with all agents and policies
ENTRYPOINT ["symbi"]
CMD ["server", "--agents-dir", "/app/agents", "--policies-dir", "/app/policies"]

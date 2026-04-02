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

# --- Stage 1: Install the symbi runtime from crates.io ---
FROM rust:latest AS builder

WORKDIR /build

# Install build dependencies required by symbi's transitive deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler libprotobuf-dev cmake pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install symbi from crates.io with required features
RUN cargo install symbi@1.9.1 --locked \
    --features "native-sandbox,interactive"

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
    perl \
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
    weasyprint \
    # --- Support ---
    python3 \
    python3-lxml \
    python3-pip \
    ca-certificates \
    jq \
    curl \
    procps \
    git \
    # --- Wordlists for gobuster/hydra ---
    wordlists \
    seclists \
    && rm -rf /var/lib/apt/lists/* \
    # nikto: Kali package is broken (missing nikto.pl), install from source
    && git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    # nikto perl dependencies (not pulled by --no-install-recommends)
    && apt-get update && apt-get install -y --no-install-recommends \
        libxml-writer-perl libio-socket-ssl-perl libnet-ssleay-perl \
        libjson-pp-perl libwhisker2-perl \
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

# Pre-download nuclei templates so first run doesn't hang
RUN nuclei -update-templates 2>/dev/null || true

# Health check: verify symbi and key tools are functional
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD symbi --version && nmap --version && msfconsole --version 2>/dev/null || exit 1

# Default: start the symbi MCP server with all agents and policies
ENTRYPOINT ["symbi"]
CMD ["server", "--agents-dir", "/app/agents", "--policies-dir", "/app/policies"]

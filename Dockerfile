# =============================================================================
# symbi-nmap-agent
# Governed AI intelligence for network reconnaissance
#
# This container packages:
#   1. nmap           -- the scanning engine (dumb tool)
#   2. symbi runtime  -- ORGA governance, Cedar policies, audit trails
#   3. Agent DSL      -- declarative agent definition
#   4. Cedar policies -- authorization rules evaluated at the Gate
#
# The key idea: nmap runs inside a sandbox governed by Symbiont's ORGA loop.
# The LLM reasons about what to scan; Cedar policies enforce what's allowed;
# the audit trail records everything. The Gate cannot be bypassed.
# =============================================================================

# --- Stage 1: Build the symbi runtime ---
FROM rust:1.82-bookworm AS builder

WORKDIR /build

# Install symbi from crates.io
# The native-sandbox feature flag includes Docker sandbox integration
RUN cargo install symbi --features native-sandbox --locked

# --- Stage 2: Runtime image ---
FROM debian:bookworm-slim

# Install nmap and minimal dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    python3 \
    python3-lxml \
    ca-certificates \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Copy symbi binary from builder
COPY --from=builder /usr/local/cargo/bin/symbi /usr/local/bin/symbi

# Create non-root user for the runtime
# nmap needs CAP_NET_RAW, granted via docker-compose or --cap-add
RUN groupadd -r symbi && useradd -r -g symbi -d /app -s /bin/bash symbi

WORKDIR /app

# Copy agent definitions, policies, and scripts
COPY agents/ ./agents/
COPY policies/ ./policies/
COPY scripts/ ./scripts/
COPY symbi.toml ./symbi.toml

# Make scripts executable
RUN chmod +x scripts/*.sh

# Create directories for runtime state
RUN mkdir -p /app/.symbiont/audit /app/.symbiont/scans /app/.symbiont/reports \
    && chown -R symbi:symbi /app

# Drop to non-root (nmap capabilities handled at container level)
USER symbi

# Health check: verify symbi and nmap are functional
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD symbi --version && nmap --version || exit 1

# Default: start the symbi MCP server so agents can be invoked
ENTRYPOINT ["symbi"]
CMD ["server", "--agents-dir", "/app/agents", "--policies-dir", "/app/policies"]

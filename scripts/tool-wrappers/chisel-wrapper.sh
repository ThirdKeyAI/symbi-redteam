#!/usr/bin/env bash
# =============================================================================
# chisel-wrapper.sh -- Sandboxed Chisel tunnel management
#
# This script wraps Chisel for creating TCP/UDP tunnels for network pivoting.
# By the time this runs, the Cedar Gate has authorized the action AND a human
# operator has approved it.
#
# Chisel runs as a long-lived background process. This wrapper starts it,
# captures the PID, and returns immediately so the MCP runtime can track it.
#
# This wrapper adds:
#   - Argument sanitization (defense in depth beyond the Gate)
#   - Mode validation (server/client)
#   - Address format validation
#   - Background process management with PID tracking
#   - Timing and resource tracking
#
# Called by the Symbiont runtime via the chisel_tunnel MCP tool.
# =============================================================================

set -euo pipefail
INJECTION_RE='[;&|$`(){}]'

# --- Configuration ---
SCAN_DIR="/app/.symbiont/scans"
LOG_DIR="/app/.symbiont/logs"
TIMEOUT_SECONDS=3600

# --- Parse arguments ---
MODE="${1:?ERROR: Mode required (server/client)}"
LISTEN_ADDR="${2:-0.0.0.0:8080}"
REMOTE="${3:-none}"
TUNNEL_SPEC="${4:-none}"
REVERSE="${5:-true}"
SCAN_ID="${6:-$(date +%s)-$$}"

LOG_FILE="${LOG_DIR}/${SCAN_ID}-chisel.log"

# --- Ensure directories exist ---
mkdir -p "$SCAN_DIR" "$LOG_DIR"

# --- Argument sanitization (defense in depth) ---

# Block shell injection in listen address
if [[ "$LISTEN_ADDR" =~ $INJECTION_RE ]]; then
    echo "ERROR: Invalid characters in listen_addr: ${LISTEN_ADDR}" >&2
    exit 2
fi

# Block shell injection in remote address
if [[ "$REMOTE" != "none" ]] && [[ "$REMOTE" =~ $INJECTION_RE ]]; then
    echo "ERROR: Invalid characters in remote: ${REMOTE}" >&2
    exit 2
fi

# Block shell injection in tunnel spec
if [[ "$TUNNEL_SPEC" != "none" ]] && [[ "$TUNNEL_SPEC" =~ $INJECTION_RE ]]; then
    echo "ERROR: Invalid characters in tunnel_spec: ${TUNNEL_SPEC}" >&2
    exit 2
fi

# Validate mode
if [[ "$MODE" != "server" ]] && [[ "$MODE" != "client" ]]; then
    echo "ERROR: Mode must be 'server' or 'client', got: ${MODE}" >&2
    exit 2
fi

# Validate listen address format (host:port)
if [[ "$MODE" == "server" ]]; then
    if ! [[ "$LISTEN_ADDR" =~ ^[a-zA-Z0-9._-]+:[0-9]+$ ]]; then
        echo "ERROR: Listen address must be in host:port format: ${LISTEN_ADDR}" >&2
        exit 2
    fi
fi

# Validate client mode has required arguments
if [[ "$MODE" == "client" ]]; then
    if [[ "$REMOTE" == "none" ]]; then
        echo "ERROR: Client mode requires remote address" >&2
        exit 2
    fi
    if [[ "$TUNNEL_SPEC" == "none" ]]; then
        echo "ERROR: Client mode requires tunnel specification" >&2
        exit 2
    fi
fi

# --- Build chisel command ---
CHISEL_CMD="chisel"
CHISEL_ARGS=()

case "$MODE" in
    server)
        CHISEL_ARGS+=(server)
        # Extract port from listen address
        PORT="${LISTEN_ADDR##*:}"
        HOST="${LISTEN_ADDR%%:*}"
        CHISEL_ARGS+=(--host "$HOST" --port "$PORT")
        if [[ "$REVERSE" == "true" ]]; then
            CHISEL_ARGS+=(--reverse)
        fi
        ;;
    client)
        CHISEL_ARGS+=(client "$REMOTE" "$TUNNEL_SPEC")
        ;;
esac

# --- Execute in background ---
echo "TUNNEL_START scan_id=${SCAN_ID} mode=${MODE} timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

START_TIME=$(date +%s%N)

# Start chisel in the background with timeout and log capture
timeout "$TIMEOUT_SECONDS" "$CHISEL_CMD" "${CHISEL_ARGS[@]}" > "$LOG_FILE" 2>&1 &
CHISEL_PID=$!

# Wait briefly to check if the process started successfully
sleep 1

if kill -0 "$CHISEL_PID" 2>/dev/null; then
    PROC_STATUS="running"
else
    # Process died within 1 second, likely an error
    wait "$CHISEL_PID" 2>/dev/null || true
    PROC_STATUS="failed"
fi

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "TUNNEL_STARTED scan_id=${SCAN_ID} pid=${CHISEL_PID} status=${PROC_STATUS} duration_ms=${DURATION_MS}" >&2

# --- Build command string for logging ---
LOG_CMD="${CHISEL_CMD} ${CHISEL_ARGS[*]}"

# --- Return JSON result ---
if [[ "$PROC_STATUS" == "running" ]]; then
    echo "{\"status\": \"success\", \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"chisel_tunnel\", \"command\": \"${LOG_CMD}\", \"pid\": ${CHISEL_PID}, \"mode\": \"${MODE}\"}"
    exit 0
else
    echo "{\"status\": \"error\", \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"chisel_tunnel\", \"command\": \"${LOG_CMD}\", \"pid\": ${CHISEL_PID}, \"mode\": \"${MODE}\"}"
    exit 1
fi

#!/usr/bin/env bash
# =============================================================================
# ligolo-wrapper.sh -- Sandboxed Ligolo-ng tunnel management
#
# This script wraps Ligolo-ng for creating network pivots through compromised
# hosts. By the time this runs, the Cedar Gate has authorized the action AND
# a human operator has approved it.
#
# Ligolo-ng creates a virtual TUN interface for full layer-3 connectivity.
# It runs as a long-lived background process. This wrapper starts it,
# captures the PID, and returns immediately so the MCP runtime can track it.
#
# This wrapper adds:
#   - Argument sanitization (defense in depth beyond the Gate)
#   - Mode validation (proxy/agent)
#   - Address format validation
#   - Background process management with PID tracking
#   - Timing and resource tracking
#
# Called by the Symbiont runtime via the ligolo_proxy MCP tool.
# =============================================================================

set -euo pipefail
INJECTION_RE='[;&|$`(){}]'

# --- Configuration ---
SCAN_DIR="/app/.symbiont/scans"
LOG_DIR="/app/.symbiont/logs"
TIMEOUT_SECONDS=3600

# --- Parse arguments ---
MODE="${1:?ERROR: Mode required (proxy/agent)}"
LISTEN_ADDR="${2:-0.0.0.0:11601}"
CONNECT_ADDR="${3:-none}"
INTERFACE="${4:-ligolo}"
SELFCERT="${5:-true}"
SCAN_ID="${6:-$(date +%s)-$$}"

LOG_FILE="${LOG_DIR}/${SCAN_ID}-ligolo.log"

# --- Ensure directories exist ---
mkdir -p "$SCAN_DIR" "$LOG_DIR"

# --- Argument sanitization (defense in depth) ---

# Block shell injection in listen address
if [[ "$LISTEN_ADDR" =~ $INJECTION_RE ]]; then
    echo "ERROR: Invalid characters in listen_addr: ${LISTEN_ADDR}" >&2
    exit 2
fi

# Block shell injection in connect address
if [[ "$CONNECT_ADDR" != "none" ]] && [[ "$CONNECT_ADDR" =~ $INJECTION_RE ]]; then
    echo "ERROR: Invalid characters in connect_addr: ${CONNECT_ADDR}" >&2
    exit 2
fi

# Block shell injection in interface name
if [[ "$INTERFACE" =~ $INJECTION_RE ]]; then
    echo "ERROR: Invalid characters in interface: ${INTERFACE}" >&2
    exit 2
fi

# Validate mode
if [[ "$MODE" != "proxy" ]] && [[ "$MODE" != "agent" ]]; then
    echo "ERROR: Mode must be 'proxy' or 'agent', got: ${MODE}" >&2
    exit 2
fi

# Validate interface name (alphanumeric and hyphens/underscores only)
if ! [[ "$INTERFACE" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "ERROR: Interface name must be alphanumeric: ${INTERFACE}" >&2
    exit 2
fi

# Validate proxy mode listen address format
if [[ "$MODE" == "proxy" ]]; then
    if ! [[ "$LISTEN_ADDR" =~ ^[a-zA-Z0-9._-]+:[0-9]+$ ]]; then
        echo "ERROR: Listen address must be in host:port format: ${LISTEN_ADDR}" >&2
        exit 2
    fi
fi

# Validate agent mode has connect address
if [[ "$MODE" == "agent" ]]; then
    if [[ "$CONNECT_ADDR" == "none" ]]; then
        echo "ERROR: Agent mode requires connect_addr" >&2
        exit 2
    fi
fi

# Defense-in-depth scope validation on the target address
# Extract the host portion from the relevant address (strip :port)
source /app/scripts/scope-check.sh
if [[ "$MODE" == "agent" ]] && [[ "$CONNECT_ADDR" != "none" ]]; then
    CONNECT_HOST="${CONNECT_ADDR%%:*}"
    validate_scope "$CONNECT_HOST"
elif [[ "$MODE" == "proxy" ]]; then
    LISTEN_HOST="${LISTEN_ADDR%%:*}"
    # Only validate non-wildcard listen addresses
    if [[ "$LISTEN_HOST" != "0.0.0.0" ]] && [[ "$LISTEN_HOST" != "127.0.0.1" ]]; then
        validate_scope "$LISTEN_HOST"
    fi
fi

# --- Build ligolo command ---
LIGOLO_CMD=""
LIGOLO_ARGS=()

case "$MODE" in
    proxy)
        LIGOLO_CMD="ligolo-proxy"
        LIGOLO_ARGS+=(-laddr "$LISTEN_ADDR")
        LIGOLO_ARGS+=(-iface "$INTERFACE")
        if [[ "$SELFCERT" == "true" ]]; then
            LIGOLO_ARGS+=(-selfcert)
        fi
        ;;
    agent)
        LIGOLO_CMD="ligolo-agent"
        LIGOLO_ARGS+=(-connect "$CONNECT_ADDR")
        LIGOLO_ARGS+=(-retry)
        if [[ "$SELFCERT" == "true" ]]; then
            LIGOLO_ARGS+=(-ignore-cert)
        fi
        ;;
esac

# --- Execute in background ---
echo "PIVOT_START scan_id=${SCAN_ID} mode=${MODE} timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

START_TIME=$(date +%s%N)

# Start ligolo in the background with timeout and log capture
timeout "$TIMEOUT_SECONDS" "$LIGOLO_CMD" "${LIGOLO_ARGS[@]}" > "$LOG_FILE" 2>&1 &
LIGOLO_PID=$!

# Wait briefly to check if the process started successfully
sleep 1

if kill -0 "$LIGOLO_PID" 2>/dev/null; then
    PROC_STATUS="running"
else
    # Process died within 1 second, likely an error
    wait "$LIGOLO_PID" 2>/dev/null || true
    PROC_STATUS="failed"
fi

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "PIVOT_STARTED scan_id=${SCAN_ID} pid=${LIGOLO_PID} status=${PROC_STATUS} duration_ms=${DURATION_MS}" >&2

# --- Build command string for logging ---
LOG_CMD="${LIGOLO_CMD} ${LIGOLO_ARGS[*]}"

# --- Return JSON result ---
if [[ "$PROC_STATUS" == "running" ]]; then
    echo "{\"status\": \"success\", \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"ligolo_proxy\", \"command\": \"${LOG_CMD}\", \"pid\": ${LIGOLO_PID}, \"mode\": \"${MODE}\"}"
    exit 0
else
    echo "{\"status\": \"error\", \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"ligolo_proxy\", \"command\": \"${LOG_CMD}\", \"pid\": ${LIGOLO_PID}, \"mode\": \"${MODE}\"}"
    exit 1
fi

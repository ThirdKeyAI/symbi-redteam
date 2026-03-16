#!/usr/bin/env bash
# =============================================================================
# smbclient-wrapper.sh -- Sandboxed smbclient SMB share access/enumeration
#
# This script is the actual "Act" in the ORGA loop. By the time this runs,
# the Cedar Gate has already authorized the scan. This wrapper adds:
#   - Argument sanitization (defense in depth beyond the Gate)
#   - Output capture for structured parsing
#   - Timing and resource tracking
#   - Clean exit codes for the runtime to interpret
#
# Called by the Symbiont runtime via the smbclient_access MCP tool.
# =============================================================================

set -euo pipefail

# --- Configuration ---
SCAN_DIR="/app/.symbiont/scans"
TIMEOUT_SECONDS=120

# --- Parse arguments ---
TARGET="${1:?ERROR: Target IP required}"
SHARE="${2:-}"
USERNAME="${3:-}"
PASSWORD="${4:-}"
SCAN_ID="${5:-smbclient-$(date +%s)-$$}"

OUTPUT_FILE="${SCAN_DIR}/${SCAN_ID}.txt"

# --- Ensure output directory exists ---
mkdir -p "$SCAN_DIR"

# --- Argument sanitization (defense in depth) ---
# Block shell injection attempts in target
if [[ "$TARGET" =~ [;\|\&\$\`\(\)\{\}] ]]; then
    echo "ERROR: Invalid characters in target: ${TARGET}" >&2
    exit 2
fi

# Validate target looks like an IP address or hostname
if ! [[ "$TARGET" =~ ^[a-zA-Z0-9._:-]+$ ]]; then
    echo "ERROR: Invalid target format: ${TARGET}" >&2
    exit 2
fi

# Block shell injection in share name
if [[ -n "$SHARE" ]] && [[ "$SHARE" =~ [;\|\&\$\`\(\)\{\}] ]]; then
    echo "ERROR: Invalid characters in share name: ${SHARE}" >&2
    exit 2
fi

# Block shell injection in username
if [[ -n "$USERNAME" ]] && [[ "$USERNAME" =~ [;\|\&\$\`\(\)\{\}] ]]; then
    echo "ERROR: Invalid characters in username: ${USERNAME}" >&2
    exit 2
fi

# Block shell injection in password
if [[ -n "$PASSWORD" ]] && [[ "$PASSWORD" =~ [;\|\&\$\`\(\)\{\}] ]]; then
    echo "ERROR: Invalid characters in password: ${PASSWORD}" >&2
    exit 2
fi

# --- Build smbclient command ---
SMBCLIENT_CMD="smbclient"
SMBCLIENT_ARGS=()

if [[ -z "$SHARE" ]]; then
    # List shares mode (anonymous)
    SMBCLIENT_ARGS+=(-L "//${TARGET}")
    if [[ -z "$USERNAME" ]]; then
        # Anonymous access
        SMBCLIENT_ARGS+=(-N)
    else
        SMBCLIENT_ARGS+=(-U "${USERNAME}%${PASSWORD}")
    fi
else
    # Access specific share
    SMBCLIENT_ARGS+=("//${TARGET}/${SHARE}")
    if [[ -z "$USERNAME" ]]; then
        SMBCLIENT_ARGS+=(-N)
    else
        SMBCLIENT_ARGS+=(-U "${USERNAME}%${PASSWORD}")
    fi
    SMBCLIENT_ARGS+=(-c "ls; exit")
fi

FULL_CMD="${SMBCLIENT_CMD} ${SMBCLIENT_ARGS[*]}"

# --- Execute ---
echo "SCAN_START scan_id=${SCAN_ID} target=${TARGET} share=${SHARE:-<list>} timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

START_TIME=$(date +%s%N)

# Run smbclient with a process timeout as a last-resort safety net
timeout "$TIMEOUT_SECONDS" $SMBCLIENT_CMD "${SMBCLIENT_ARGS[@]}" > "$OUTPUT_FILE" 2>&1 || true

EXIT_CODE=${PIPESTATUS[0]:-0}

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "SCAN_END scan_id=${SCAN_ID} exit_code=${EXIT_CODE} duration_ms=${DURATION_MS}" >&2

# --- Log output to stderr for runtime visibility ---
if [[ -f "$OUTPUT_FILE" ]]; then
    while IFS= read -r line; do
        echo "[smbclient] $line" >&2
    done < "$OUTPUT_FILE"
fi

# --- Return structured output to the runtime ---
if [[ -f "$OUTPUT_FILE" ]] && [[ -s "$OUTPUT_FILE" ]]; then
    echo "{\"status\": \"success\", \"output_file\": \"${OUTPUT_FILE}\", \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"smbclient_access\", \"command\": \"${FULL_CMD}\"}"
    exit 0
else
    echo "{\"status\": \"error\", \"exit_code\": ${EXIT_CODE}, \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"smbclient_access\", \"command\": \"${FULL_CMD}\"}"
    exit 1
fi

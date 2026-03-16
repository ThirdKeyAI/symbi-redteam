#!/usr/bin/env bash
# =============================================================================
# dns-wrapper.sh -- Sandboxed DNS enumeration
#
# Performs DNS lookups using dig and host against a target domain. By the time
# this runs, the Cedar Gate has already authorized the enumeration. This wrapper
# adds:
#   - Argument sanitization (defense in depth beyond the Gate)
#   - Output capture to file for structured parsing
#   - Timing and resource tracking
#   - Clean exit codes for the runtime to interpret
#
# Called by the Symbiont runtime via the dns_enumerate MCP tool.
# =============================================================================

set -euo pipefail

# --- Configuration ---
SCAN_DIR="/app/.symbiont/scans"
TIMEOUT_SECONDS="${DNS_TIMEOUT:-30}"

# --- Parse arguments ---
TARGET="${1:?ERROR: Target domain required}"
RECORD_TYPE="${2:-A}"
SCAN_ID="${3:-$(date +%s)-$$}"

OUTPUT_FILE="${SCAN_DIR}/${SCAN_ID}-dns.txt"

# --- Ensure output directory exists ---
mkdir -p "$SCAN_DIR"

# --- Argument sanitization (defense in depth) ---

# Block shell injection attempts in target
if [[ "$TARGET" =~ [;\|\&\$\`\(\)\{\}\<\>\!\#\~\'] ]]; then
    echo "ERROR: Invalid characters in target: ${TARGET}" >&2
    exit 2
fi

# Block whitespace in target
if [[ "$TARGET" =~ [[:space:]] ]]; then
    echo "ERROR: Whitespace not allowed in target: ${TARGET}" >&2
    exit 2
fi

# Target must look like a domain name or IP address
if ! [[ "$TARGET" =~ ^[a-zA-Z0-9._:-]+$ ]]; then
    echo "ERROR: Target does not look like a valid domain: ${TARGET}" >&2
    exit 2
fi

# Validate record type
VALID_TYPES="A AAAA MX NS TXT ANY SOA CNAME PTR SRV"
RECORD_TYPE_UPPER=$(echo "$RECORD_TYPE" | tr '[:lower:]' '[:upper:]')
if ! echo "$VALID_TYPES" | grep -qw "$RECORD_TYPE_UPPER"; then
    echo "ERROR: Unknown record type: ${RECORD_TYPE}" >&2
    exit 2
fi

# Block shell injection in record type (extra safety)
if [[ "$RECORD_TYPE_UPPER" =~ [;\|\&\$\`\(\)] ]]; then
    echo "ERROR: Invalid characters in record type: ${RECORD_TYPE}" >&2
    exit 2
fi

# --- Build commands ---
DIG_CMD="dig"
DIG_ARGS=("$TARGET" "$RECORD_TYPE_UPPER" "+noall" "+answer" "+authority" "+additional")

HOST_CMD="host"
HOST_ARGS=("$TARGET")

FULL_CMD="${DIG_CMD} ${DIG_ARGS[*]}"

# --- Execute ---
echo "DNS_START scan_id=${SCAN_ID} target=${TARGET} record_type=${RECORD_TYPE_UPPER} timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

START_TIME=$(date +%s%N)

{
    echo "=== DIG RESULTS (${RECORD_TYPE_UPPER}) ==="
    echo "Command: ${DIG_CMD} ${DIG_ARGS[*]}"
    echo "---"
    if timeout "$TIMEOUT_SECONDS" $DIG_CMD "${DIG_ARGS[@]}" 2>&1; then
        DIG_EXIT=0
    else
        DIG_EXIT=$?
        echo "dig exited with code: ${DIG_EXIT}"
    fi
    echo ""
    echo "=== HOST RESULTS ==="
    echo "Command: ${HOST_CMD} ${HOST_ARGS[*]}"
    echo "---"
    if timeout "$TIMEOUT_SECONDS" $HOST_CMD "${HOST_ARGS[@]}" 2>&1; then
        HOST_EXIT=0
    else
        HOST_EXIT=$?
        echo "host exited with code: ${HOST_EXIT}"
    fi
} > "$OUTPUT_FILE"

# Use the dig exit code as the primary result
EXIT_CODE=${DIG_EXIT:-0}

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "DNS_END scan_id=${SCAN_ID} exit_code=${EXIT_CODE} duration_ms=${DURATION_MS}" >&2

# --- Return structured JSON to the runtime ---
if [[ $EXIT_CODE -eq 0 ]] && [[ -f "$OUTPUT_FILE" ]]; then
    echo "{\"status\": \"success\", \"output_file\": \"${OUTPUT_FILE}\", \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"dns_enumerate\", \"command\": \"${FULL_CMD}\"}"
    exit 0
else
    echo "{\"status\": \"error\", \"exit_code\": ${EXIT_CODE}, \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"dns_enumerate\", \"command\": \"${FULL_CMD}\"}"
    exit 1
fi

#!/usr/bin/env bash
# =============================================================================
# whois-wrapper.sh -- Sandboxed whois execution
#
# Performs a WHOIS lookup against a target IP or domain. By the time this runs,
# the Cedar Gate has already authorized the lookup. This wrapper adds:
#   - Argument sanitization (defense in depth beyond the Gate)
#   - Output capture to file for structured parsing
#   - Timing and resource tracking
#   - Clean exit codes for the runtime to interpret
#
# Called by the Symbiont runtime via the whois_lookup MCP tool.
# =============================================================================

set -euo pipefail
INJECTION_RE='[;&|$`(){}]'

# --- Configuration ---
SCAN_DIR="/app/.symbiont/scans"
TIMEOUT_SECONDS="${WHOIS_TIMEOUT:-30}"

# --- Parse arguments ---
TARGET="${1:?ERROR: Target IP or domain required}"
SCAN_ID="${2:-$(date +%s)-$$}"

OUTPUT_FILE="${SCAN_DIR}/${SCAN_ID}-whois.txt"

# --- Ensure output directory exists ---
mkdir -p "$SCAN_DIR"

# --- Argument sanitization (defense in depth) ---

# Block shell injection attempts in target
if [[ "$TARGET" =~ $INJECTION_RE ]]; then
    echo "ERROR: Invalid characters in target: ${TARGET}" >&2
    exit 2
fi

# Block whitespace in target
if [[ "$TARGET" =~ [[:space:]] ]]; then
    echo "ERROR: Whitespace not allowed in target: ${TARGET}" >&2
    exit 2
fi

# Target must look like a domain or IP address
if ! [[ "$TARGET" =~ ^[a-zA-Z0-9._:/-]+$ ]]; then
    echo "ERROR: Target does not look like a valid domain or IP: ${TARGET}" >&2
    exit 2
fi

# Block obviously wrong targets
if [[ "$TARGET" == "0.0.0.0" ]] || [[ "$TARGET" == "255.255.255.255" ]]; then
    echo "ERROR: Invalid target address: ${TARGET}" >&2
    exit 2
fi

# Defense-in-depth scope validation
source /app/scripts/scope-check.sh
validate_scope "$TARGET"

# --- Build command ---
WHOIS_CMD="whois"
WHOIS_ARGS=("$TARGET")

FULL_CMD="${WHOIS_CMD} ${WHOIS_ARGS[*]}"

# --- Execute ---
echo "WHOIS_START scan_id=${SCAN_ID} target=${TARGET} timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

START_TIME=$(date +%s%N)

# Run whois with a process timeout as a last-resort safety net
if timeout "$TIMEOUT_SECONDS" $WHOIS_CMD "${WHOIS_ARGS[@]}" > "$OUTPUT_FILE" 2>&1; then
    EXIT_CODE=0
else
    EXIT_CODE=$?
fi

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "WHOIS_END scan_id=${SCAN_ID} exit_code=${EXIT_CODE} duration_ms=${DURATION_MS}" >&2

# --- Return structured JSON to the runtime ---
if [[ $EXIT_CODE -eq 0 ]] && [[ -f "$OUTPUT_FILE" ]]; then
    echo "{\"status\": \"success\", \"output_file\": \"${OUTPUT_FILE}\", \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"whois_lookup\", \"command\": \"${FULL_CMD}\"}"
    exit 0
else
    echo "{\"status\": \"error\", \"exit_code\": ${EXIT_CODE}, \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"whois_lookup\", \"command\": \"${FULL_CMD}\"}"
    exit 1
fi

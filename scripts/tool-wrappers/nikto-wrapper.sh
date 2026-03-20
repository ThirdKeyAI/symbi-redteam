#!/usr/bin/env bash
# =============================================================================
# nikto-wrapper.sh -- Sandboxed Nikto web vulnerability scanner execution
#
# This script is the actual "Act" in the ORGA loop. By the time this runs,
# the Cedar Gate has already authorized the scan. This wrapper adds:
#   - Argument sanitization (defense in depth beyond the Gate)
#   - Output capture in JSON format for structured parsing
#   - Timing and resource tracking
#   - Clean exit codes for the runtime to interpret
#
# Called by the Symbiont runtime via the nikto_scan MCP tool.
# =============================================================================

set -euo pipefail
INJECTION_RE='[;&|$`(){}]'

# --- Configuration ---
SCAN_DIR="/app/.symbiont/scans"
TIMEOUT_SECONDS=600

# --- Parse arguments ---
TARGET="${1:?ERROR: Target URL required}"
TUNING="${2:-0}"
OUTPUT_FORMAT="${3:-json}"
SCAN_ID="${4:-nikto-$(date +%s)-$$}"

OUTPUT_FILE="${SCAN_DIR}/${SCAN_ID}.json"

# --- Ensure output directory exists ---
mkdir -p "$SCAN_DIR"

# --- Argument sanitization (defense in depth) ---
# Block shell injection attempts in target
if [[ "$TARGET" =~ $INJECTION_RE ]]; then
    echo "ERROR: Invalid characters in target: ${TARGET}" >&2
    exit 2
fi

# Validate target looks like a URL
if ! [[ "$TARGET" =~ ^https?:// ]]; then
    echo "ERROR: Target must be a URL starting with http:// or https://: ${TARGET}" >&2
    exit 2
fi

# Validate tuning is a digit 0-9
if ! [[ "$TUNING" =~ ^[0-9]$ ]]; then
    echo "ERROR: Tuning must be a single digit 0-9: ${TUNING}" >&2
    exit 2
fi

# Validate output format
if [[ "$OUTPUT_FORMAT" != "json" ]] && [[ "$OUTPUT_FORMAT" != "xml" ]]; then
    echo "ERROR: Output format must be 'json' or 'xml': ${OUTPUT_FORMAT}" >&2
    exit 2
fi

# Defense-in-depth scope validation
source /app/scripts/scope-check.sh
SCOPE_HOST=$(echo "$TARGET" | sed -E 's|https?://||; s|:[0-9]+.*||; s|/.*||')
validate_scope "$SCOPE_HOST"

# --- Determine format flag ---
if [[ "$OUTPUT_FORMAT" == "json" ]]; then
    FORMAT_FLAG="json"
else
    FORMAT_FLAG="xml"
fi

# --- Build nikto command ---
NIKTO_CMD="nikto"
NIKTO_ARGS=(
    -h "$TARGET"
    -Tuning "$TUNING"
    -Format "$FORMAT_FLAG"
    -output "$OUTPUT_FILE"
    -nointeractive
)

FULL_CMD="${NIKTO_CMD} ${NIKTO_ARGS[*]}"

# --- Execute ---
echo "SCAN_START scan_id=${SCAN_ID} target=${TARGET} tuning=${TUNING} timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

START_TIME=$(date +%s%N)

# Run nikto with a process timeout as a last-resort safety net
timeout "$TIMEOUT_SECONDS" $NIKTO_CMD "${NIKTO_ARGS[@]}" 2>&1 | while IFS= read -r line; do
    echo "[nikto] $line" >&2
done

EXIT_CODE=${PIPESTATUS[0]}

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "SCAN_END scan_id=${SCAN_ID} exit_code=${EXIT_CODE} duration_ms=${DURATION_MS}" >&2

# --- Return structured output to the runtime ---
if [[ $EXIT_CODE -eq 0 ]] && [[ -f "$OUTPUT_FILE" ]]; then
    echo "{\"status\": \"success\", \"output_file\": \"${OUTPUT_FILE}\", \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"nikto_scan\", \"command\": \"${FULL_CMD}\"}"
    exit 0
else
    echo "{\"status\": \"error\", \"exit_code\": ${EXIT_CODE}, \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"nikto_scan\", \"command\": \"${FULL_CMD}\"}"
    exit 1
fi

#!/usr/bin/env bash
# =============================================================================
# enum4linux-wrapper.sh -- Sandboxed enum4linux SMB/NetBIOS enumeration
#
# This script is the actual "Act" in the ORGA loop. By the time this runs,
# the Cedar Gate has already authorized the scan. This wrapper adds:
#   - Argument sanitization (defense in depth beyond the Gate)
#   - Output capture for structured parsing
#   - Timing and resource tracking
#   - Clean exit codes for the runtime to interpret
#
# Called by the Symbiont runtime via the enum4linux_scan MCP tool.
# =============================================================================

set -euo pipefail
INJECTION_RE='[;&|$`(){}]'

# --- Configuration ---
SCAN_DIR="/app/.symbiont/scans"
TIMEOUT_SECONDS=300

# --- Parse arguments ---
TARGET="${1:?ERROR: Target IP required}"
SCAN_TYPE="${2:-all}"
SCAN_ID="${3:-enum4linux-$(date +%s)-$$}"

OUTPUT_FILE="${SCAN_DIR}/${SCAN_ID}.txt"

# --- Ensure output directory exists ---
mkdir -p "$SCAN_DIR"

# --- Argument sanitization (defense in depth) ---
# Block shell injection attempts in target
if [[ "$TARGET" =~ $INJECTION_RE ]]; then
    echo "ERROR: Invalid characters in target: ${TARGET}" >&2
    exit 2
fi

# Validate target looks like an IP address or hostname
if ! [[ "$TARGET" =~ ^[a-zA-Z0-9._:-]+$ ]]; then
    echo "ERROR: Invalid target format: ${TARGET}" >&2
    exit 2
fi

# Map scan_type enum to specific flags (no free-form options accepted)
VALID_TYPES="all users shares policies groups"
if ! echo "$VALID_TYPES" | grep -qw "$SCAN_TYPE"; then
    echo "ERROR: Unknown scan_type: ${SCAN_TYPE} (allowed: ${VALID_TYPES})" >&2
    exit 2
fi

case "$SCAN_TYPE" in
    all)      OPTIONS="-a" ;;
    users)    OPTIONS="-U" ;;
    shares)   OPTIONS="-S" ;;
    policies) OPTIONS="-P" ;;
    groups)   OPTIONS="-G" ;;
esac

# Defense-in-depth scope validation
source /app/scripts/scope-check.sh
validate_scope "$TARGET"

# --- Build enum4linux command ---
ENUM4LINUX_CMD="enum4linux"
FULL_CMD="${ENUM4LINUX_CMD} ${OPTIONS} ${TARGET}"

# --- Execute ---
echo "SCAN_START scan_id=${SCAN_ID} target=${TARGET} scan_type=${SCAN_TYPE} timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

START_TIME=$(date +%s%N)

# Run enum4linux with a process timeout as a last-resort safety net
# enum4linux writes to stdout, so we capture it to a file
timeout "$TIMEOUT_SECONDS" "$ENUM4LINUX_CMD" "$OPTIONS" "$TARGET" > "$OUTPUT_FILE" 2>&1 || true

EXIT_CODE=${PIPESTATUS[0]:-0}

# enum4linux often returns non-zero even on partial success, so we check
# if output was produced rather than relying solely on exit code
if [[ ! -f "$OUTPUT_FILE" ]] || [[ ! -s "$OUTPUT_FILE" ]]; then
    EXIT_CODE=1
fi

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "SCAN_END scan_id=${SCAN_ID} exit_code=${EXIT_CODE} duration_ms=${DURATION_MS}" >&2

# --- Log output to stderr for runtime visibility ---
while IFS= read -r line; do
    echo "[enum4linux] $line" >&2
done < "$OUTPUT_FILE"

# --- Return structured output to the runtime ---
if [[ -f "$OUTPUT_FILE" ]] && [[ -s "$OUTPUT_FILE" ]]; then
    echo "{\"status\": \"success\", \"output_file\": \"${OUTPUT_FILE}\", \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"enum4linux_scan\", \"command\": \"${FULL_CMD}\"}"
    exit 0
else
    echo "{\"status\": \"error\", \"exit_code\": ${EXIT_CODE}, \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"enum4linux_scan\", \"command\": \"${FULL_CMD}\"}"
    exit 1
fi

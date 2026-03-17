#!/usr/bin/env bash
# =============================================================================
# gobuster-wrapper.sh -- Sandboxed Gobuster directory/DNS/vhost brute-force
#
# This script is the actual "Act" in the ORGA loop. By the time this runs,
# the Cedar Gate has already authorized the scan. This wrapper adds:
#   - Argument sanitization (defense in depth beyond the Gate)
#   - Output capture for structured parsing
#   - Timing and resource tracking
#   - Clean exit codes for the runtime to interpret
#
# Called by the Symbiont runtime via the gobuster_scan MCP tool.
# =============================================================================

set -euo pipefail
INJECTION_RE='[;&|$`(){}]'

# --- Configuration ---
SCAN_DIR="/app/.symbiont/scans"
TIMEOUT_SECONDS=600

# --- Parse arguments ---
TARGET="${1:?ERROR: Target URL required}"
MODE="${2:-dir}"
WORDLIST="${3:-/usr/share/seclists/Discovery/Web-Content/common.txt}"
EXTENSIONS="${4:-php,html,txt}"
SCAN_ID="${5:-gobuster-$(date +%s)-$$}"

OUTPUT_FILE="${SCAN_DIR}/${SCAN_ID}.txt"

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

# Validate mode
VALID_MODES="dir dns vhost"
if ! echo "$VALID_MODES" | grep -qw "$MODE"; then
    echo "ERROR: Invalid mode '${MODE}'. Must be one of: ${VALID_MODES}" >&2
    exit 2
fi

# Validate wordlist path (no shell metacharacters, must be absolute path)
if [[ "$WORDLIST" =~ $INJECTION_RE ]]; then
    echo "ERROR: Invalid characters in wordlist path: ${WORDLIST}" >&2
    exit 2
fi

if [[ ! "$WORDLIST" =~ ^/ ]]; then
    echo "ERROR: Wordlist must be an absolute path: ${WORDLIST}" >&2
    exit 2
fi

# Validate extensions (only alphanumeric and commas allowed)
if [[ "$EXTENSIONS" =~ [^a-zA-Z0-9,] ]]; then
    echo "ERROR: Extensions must be comma-separated alphanumeric values: ${EXTENSIONS}" >&2
    exit 2
fi

# --- Build gobuster command ---
GOBUSTER_CMD="gobuster"
GOBUSTER_ARGS=("$MODE")

case "$MODE" in
    dir)
        GOBUSTER_ARGS+=(
            -u "$TARGET"
            -w "$WORDLIST"
            -x "$EXTENSIONS"
            -o "$OUTPUT_FILE"
            --no-color
            -q
        )
        ;;
    dns)
        GOBUSTER_ARGS+=(
            -d "$TARGET"
            -w "$WORDLIST"
            -o "$OUTPUT_FILE"
            --no-color
            -q
        )
        ;;
    vhost)
        GOBUSTER_ARGS+=(
            -u "$TARGET"
            -w "$WORDLIST"
            -o "$OUTPUT_FILE"
            --no-color
            -q
        )
        ;;
esac

FULL_CMD="${GOBUSTER_CMD} ${GOBUSTER_ARGS[*]}"

# --- Execute ---
echo "SCAN_START scan_id=${SCAN_ID} target=${TARGET} mode=${MODE} timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

START_TIME=$(date +%s%N)

# Run gobuster with a process timeout as a last-resort safety net
timeout "$TIMEOUT_SECONDS" $GOBUSTER_CMD "${GOBUSTER_ARGS[@]}" 2>&1 | while IFS= read -r line; do
    echo "[gobuster] $line" >&2
done

EXIT_CODE=${PIPESTATUS[0]}

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "SCAN_END scan_id=${SCAN_ID} exit_code=${EXIT_CODE} duration_ms=${DURATION_MS}" >&2

# --- Return structured output to the runtime ---
if [[ $EXIT_CODE -eq 0 ]] && [[ -f "$OUTPUT_FILE" ]]; then
    echo "{\"status\": \"success\", \"output_file\": \"${OUTPUT_FILE}\", \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"gobuster_scan\", \"command\": \"${FULL_CMD}\"}"
    exit 0
else
    echo "{\"status\": \"error\", \"exit_code\": ${EXIT_CODE}, \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"gobuster_scan\", \"command\": \"${FULL_CMD}\"}"
    exit 1
fi

#!/usr/bin/env bash
# =============================================================================
# nuclei-wrapper.sh -- Sandboxed Nuclei execution
#
# This script is the actual "Act" in the ORGA loop. By the time this runs,
# the Cedar Gate has already authorized the scan. This wrapper adds:
#   - Argument sanitization (defense in depth beyond the Gate)
#   - Output capture in JSONL format for structured parsing
#   - Timing and resource tracking
#   - Clean exit codes for the runtime to interpret
#
# Called by the Symbiont runtime via the nuclei_scan MCP tool.
# =============================================================================

set -euo pipefail
INJECTION_RE='[;&|$`(){}]'

# --- Configuration ---
SCAN_DIR="/app/.symbiont/scans"
NUCLEI_TIMEOUT="${NUCLEI_TIMEOUT:-900}"

# --- Parse arguments ---
TARGET="${1:?ERROR: Target URL or IP required}"
TEMPLATES="${2:-}"
SEVERITY_FILTER="${3:-critical,high,medium}"
RATE_LIMIT="${4:-150}"
SCAN_ID="${5:-$(date +%s)-$$}"

OUTPUT_FILE="${SCAN_DIR}/${SCAN_ID}-nuclei.jsonl"

# --- Ensure output directory exists ---
mkdir -p "$SCAN_DIR"

# --- Argument sanitization (defense in depth) ---
# Block shell injection attempts in target
if [[ "$TARGET" =~ $INJECTION_RE ]]; then
    echo "ERROR: Invalid characters in target: ${TARGET}" >&2
    exit 2
fi

# Validate severity filter values
IFS=',' read -ra SEVERITIES <<< "$SEVERITY_FILTER"
VALID_SEVERITIES="critical high medium low info"
for sev in "${SEVERITIES[@]}"; do
    sev_trimmed=$(echo "$sev" | tr -d '[:space:]')
    if ! echo "$VALID_SEVERITIES" | grep -qw "$sev_trimmed"; then
        echo "ERROR: Invalid severity level: ${sev_trimmed}" >&2
        exit 2
    fi
done

# Validate rate limit is a positive integer
if ! [[ "$RATE_LIMIT" =~ ^[0-9]+$ ]] || [[ "$RATE_LIMIT" -eq 0 ]]; then
    echo "ERROR: Rate limit must be a positive integer: ${RATE_LIMIT}" >&2
    exit 2
fi

# Cap rate limit to prevent abuse
if [[ "$RATE_LIMIT" -gt 1000 ]]; then
    RATE_LIMIT=1000
fi

# Block shell injection in templates
if [[ -n "$TEMPLATES" ]] && [[ "$TEMPLATES" =~ $INJECTION_RE ]]; then
    echo "ERROR: Invalid characters in templates: ${TEMPLATES}" >&2
    exit 2
fi

# --- Build nuclei command ---
NUCLEI_CMD="nuclei"
NUCLEI_ARGS=(
    -u "$TARGET"
    -severity "$SEVERITY_FILTER"
    -rate-limit "$RATE_LIMIT"
    -jsonl
    -o "$OUTPUT_FILE"
    -silent
)

# Add specific templates if provided
if [[ -n "$TEMPLATES" ]]; then
    NUCLEI_ARGS+=(-t "$TEMPLATES")
fi

# --- Execute ---
echo "SCAN_START scan_id=${SCAN_ID} target=${TARGET} tool=nuclei severity=${SEVERITY_FILTER} timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

START_TIME=$(date +%s%N)

# Run nuclei with a process timeout as a last-resort safety net
timeout "$NUCLEI_TIMEOUT" $NUCLEI_CMD "${NUCLEI_ARGS[@]}" 2>&1 | while IFS= read -r line; do
    echo "[nuclei] $line" >&2
done

EXIT_CODE=${PIPESTATUS[0]}

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "SCAN_END scan_id=${SCAN_ID} exit_code=${EXIT_CODE} duration_ms=${DURATION_MS}" >&2

# --- Count findings ---
FINDINGS_COUNT=0
if [[ -f "$OUTPUT_FILE" ]]; then
    FINDINGS_COUNT=$(wc -l < "$OUTPUT_FILE" | tr -d '[:space:]')
fi

# --- Return structured output to the runtime ---
FULL_CMD="${NUCLEI_CMD} ${NUCLEI_ARGS[*]}"

if [[ $EXIT_CODE -eq 0 ]]; then
    cat <<JSONEOF
{"status": "success", "output_file": "${OUTPUT_FILE}", "scan_id": "${SCAN_ID}", "duration_ms": ${DURATION_MS}, "tool": "nuclei_scan", "command": "${FULL_CMD}", "findings_count": ${FINDINGS_COUNT}}
JSONEOF
    exit 0
else
    cat <<JSONEOF
{"status": "error", "exit_code": ${EXIT_CODE}, "scan_id": "${SCAN_ID}", "tool": "nuclei_scan", "command": "${FULL_CMD}", "findings_count": ${FINDINGS_COUNT}}
JSONEOF
    exit 1
fi

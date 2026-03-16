#!/usr/bin/env bash
# =============================================================================
# pypykatz-wrapper.sh -- Sandboxed pypykatz credential extraction
#
# This script wraps pypykatz for parsing SAM/SECURITY/SYSTEM registry hives
# and LSASS minidump files. By the time this runs, the Cedar Gate has
# authorized the action AND a human operator has approved it.
#
# This wrapper adds:
#   - Argument sanitization (defense in depth beyond the Gate)
#   - Source type validation
#   - Output capture in JSON format
#   - Credential counting for summary reporting
#   - Timing and resource tracking
#
# Called by the Symbiont runtime via the pypykatz_dump MCP tool.
# =============================================================================

set -euo pipefail

# --- Configuration ---
SCAN_DIR="/app/.symbiont/scans"
TIMEOUT_SECONDS=120

# --- Parse arguments ---
SOURCE="${1:?ERROR: Source path required}"
SOURCE_TYPE="${2:?ERROR: Source type required (file/registry/lsass)}"
TARGET="${3:-none}"
SCAN_ID="${4:-$(date +%s)-$$}"

OUTPUT_FILE="${SCAN_DIR}/${SCAN_ID}-pypykatz.json"

# --- Ensure output directory exists ---
mkdir -p "$SCAN_DIR"

# --- Argument sanitization (defense in depth) ---

# Block shell injection attempts in source path
if [[ "$SOURCE" =~ [;\|\&\$\`\(\)\{\}] ]]; then
    echo "ERROR: Invalid characters in source: ${SOURCE}" >&2
    exit 2
fi

# Block shell injection in target
if [[ "$TARGET" != "none" ]] && [[ "$TARGET" =~ [;\|\&\$\`\(\)\{\}] ]]; then
    echo "ERROR: Invalid characters in target: ${TARGET}" >&2
    exit 2
fi

# Validate source type
VALID_TYPES="file registry lsass"
if ! echo "$VALID_TYPES" | grep -qw "$SOURCE_TYPE"; then
    echo "ERROR: Unknown source type: ${SOURCE_TYPE}. Must be one of: ${VALID_TYPES}" >&2
    exit 2
fi

# Validate that source file exists (for file-based operations)
if [[ "$SOURCE_TYPE" == "file" ]] || [[ "$SOURCE_TYPE" == "registry" ]] || [[ "$SOURCE_TYPE" == "lsass" ]]; then
    if [[ ! -f "$SOURCE" ]]; then
        echo "ERROR: Source file not found: ${SOURCE}" >&2
        exit 2
    fi
fi

# --- Build pypykatz command based on source type ---
PYPYKATZ_CMD="pypykatz"
PYPYKATZ_ARGS=()

case "$SOURCE_TYPE" in
    file)
        # Parse SAM/SECURITY/SYSTEM registry hive files
        PYPYKATZ_ARGS+=(registry "$SOURCE" --json)
        ;;
    registry)
        # Parse exported registry hives
        PYPYKATZ_ARGS+=(registry "$SOURCE" --json)
        ;;
    lsass)
        # Parse LSASS minidump file
        PYPYKATZ_ARGS+=(lsa minidump "$SOURCE" --json)
        ;;
esac

# --- Execute ---
echo "DUMP_START scan_id=${SCAN_ID} source=${SOURCE} source_type=${SOURCE_TYPE} timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

START_TIME=$(date +%s%N)

# Run pypykatz with timeout, capture output to file
EXEC_SUCCESS=true
timeout "$TIMEOUT_SECONDS" "$PYPYKATZ_CMD" "${PYPYKATZ_ARGS[@]}" > "$OUTPUT_FILE" 2>/dev/null || EXEC_SUCCESS=false

EXIT_CODE=$?

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "DUMP_END scan_id=${SCAN_ID} exit_code=${EXIT_CODE} duration_ms=${DURATION_MS}" >&2

# --- Count extracted credentials ---
CRED_COUNT=0
if [[ -f "$OUTPUT_FILE" ]] && [[ -s "$OUTPUT_FILE" ]]; then
    # Count credential entries in the JSON output
    # Look for username/password/hash entries across different credential types
    CRED_COUNT=$(python3 -c "
import json, sys
try:
    with open('${OUTPUT_FILE}') as f:
        data = json.load(f)
    count = 0
    # Handle LSASS dump format
    if isinstance(data, dict):
        for session_key in data.get('logon_sessions', {}):
            session = data['logon_sessions'][session_key]
            if session.get('username', ''):
                count += 1
        # Handle registry hive format
        for sam_key in data.get('sam_hashes', []):
            count += 1
        for secret in data.get('secrets', []):
            count += 1
        for cached in data.get('cached', []):
            count += 1
    print(count)
except Exception:
    print(0)
" 2>/dev/null || echo "0")
fi

# --- Build command string for logging ---
LOG_CMD="${PYPYKATZ_CMD} ${PYPYKATZ_ARGS[*]}"

# --- Return JSON result ---
if [[ "$EXEC_SUCCESS" == true ]] && [[ -f "$OUTPUT_FILE" ]]; then
    echo "{\"status\": \"success\", \"output_file\": \"${OUTPUT_FILE}\", \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"pypykatz_dump\", \"command\": \"${LOG_CMD}\", \"credentials_count\": ${CRED_COUNT}}"
    exit 0
else
    echo "{\"status\": \"error\", \"output_file\": \"${OUTPUT_FILE}\", \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"pypykatz_dump\", \"command\": \"${LOG_CMD}\", \"credentials_count\": 0}"
    exit 1
fi

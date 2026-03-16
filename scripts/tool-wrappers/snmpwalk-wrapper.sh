#!/usr/bin/env bash
# =============================================================================
# snmpwalk-wrapper.sh -- Sandboxed snmpwalk SNMP enumeration
#
# This script is the actual "Act" in the ORGA loop. By the time this runs,
# the Cedar Gate has already authorized the scan. This wrapper adds:
#   - Argument sanitization (defense in depth beyond the Gate)
#   - Output capture for structured parsing
#   - Timing and resource tracking
#   - Clean exit codes for the runtime to interpret
#
# Called by the Symbiont runtime via the snmpwalk_enum MCP tool.
# =============================================================================

set -euo pipefail

# --- Configuration ---
SCAN_DIR="/app/.symbiont/scans"
TIMEOUT_SECONDS=300

# --- Parse arguments ---
TARGET="${1:?ERROR: Target IP required}"
COMMUNITY="${2:-public}"
VERSION="${3:-2c}"
OID="${4:-}"
SCAN_ID="${5:-snmpwalk-$(date +%s)-$$}"

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

# Block shell injection in community string
if [[ "$COMMUNITY" =~ [;\|\&\$\`\(\)\{\}] ]]; then
    echo "ERROR: Invalid characters in community string: ${COMMUNITY}" >&2
    exit 2
fi

# Validate SNMP version
VALID_VERSIONS="1 2c 3"
if ! echo "$VALID_VERSIONS" | grep -qw "$VERSION"; then
    echo "ERROR: Invalid SNMP version '${VERSION}'. Must be one of: ${VALID_VERSIONS}" >&2
    exit 2
fi

# Validate OID (only digits, dots, and common MIB names allowed)
if [[ -n "$OID" ]] && ! [[ "$OID" =~ ^[a-zA-Z0-9._:-]+$ ]]; then
    echo "ERROR: Invalid OID format: ${OID}" >&2
    exit 2
fi

# --- Build snmpwalk command ---
SNMPWALK_CMD="snmpwalk"
SNMPWALK_ARGS=(
    "-v${VERSION}"
    -c "$COMMUNITY"
    "$TARGET"
)

# Append OID if specified
if [[ -n "$OID" ]]; then
    SNMPWALK_ARGS+=("$OID")
fi

FULL_CMD="${SNMPWALK_CMD} ${SNMPWALK_ARGS[*]}"

# --- Execute ---
echo "SCAN_START scan_id=${SCAN_ID} target=${TARGET} community=${COMMUNITY} version=${VERSION} timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

START_TIME=$(date +%s%N)

# Run snmpwalk with a process timeout as a last-resort safety net
timeout "$TIMEOUT_SECONDS" $SNMPWALK_CMD "${SNMPWALK_ARGS[@]}" > "$OUTPUT_FILE" 2>&1 || true

EXIT_CODE=${PIPESTATUS[0]:-0}

# snmpwalk returns non-zero when it reaches end of MIB, which is normal
# Check if we got output rather than relying solely on exit code
if [[ ! -f "$OUTPUT_FILE" ]] || [[ ! -s "$OUTPUT_FILE" ]]; then
    EXIT_CODE=1
fi

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "SCAN_END scan_id=${SCAN_ID} exit_code=${EXIT_CODE} duration_ms=${DURATION_MS}" >&2

# --- Log output to stderr for runtime visibility ---
if [[ -f "$OUTPUT_FILE" ]]; then
    while IFS= read -r line; do
        echo "[snmpwalk] $line" >&2
    done < "$OUTPUT_FILE"
fi

# --- Return structured output to the runtime ---
if [[ -f "$OUTPUT_FILE" ]] && [[ -s "$OUTPUT_FILE" ]]; then
    echo "{\"status\": \"success\", \"output_file\": \"${OUTPUT_FILE}\", \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"snmpwalk_enum\", \"command\": \"${FULL_CMD}\"}"
    exit 0
else
    echo "{\"status\": \"error\", \"exit_code\": ${EXIT_CODE}, \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"snmpwalk_enum\", \"command\": \"${FULL_CMD}\"}"
    exit 1
fi

#!/usr/bin/env bash
# =============================================================================
# amass-wrapper.sh -- Sandboxed Amass subdomain enumeration
#
# Performs subdomain enumeration against a target domain using OWASP Amass.
# By the time this runs, the Cedar Gate has already authorized the enumeration.
# This wrapper adds:
#   - Argument sanitization (defense in depth beyond the Gate)
#   - Output capture in JSON format for structured parsing
#   - Timing and resource tracking
#   - Clean exit codes for the runtime to interpret
#
# Called by the Symbiont runtime via the amass_enum MCP tool.
# =============================================================================

set -euo pipefail
INJECTION_RE='[;&|$`(){}]'

# --- Configuration ---
SCAN_DIR="/app/.symbiont/scans"
TIMEOUT_SECONDS="${AMASS_TIMEOUT:-600}"

# --- Parse arguments ---
TARGET="${1:?ERROR: Target domain required}"
PASSIVE_ONLY="${2:-true}"
SCAN_ID="${3:-$(date +%s)-$$}"

OUTPUT_FILE="${SCAN_DIR}/${SCAN_ID}-amass.json"

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

# Target must look like a domain name (letters, digits, hyphens, dots)
if ! [[ "$TARGET" =~ ^[a-zA-Z0-9.-]+$ ]]; then
    echo "ERROR: Target does not look like a valid domain: ${TARGET}" >&2
    exit 2
fi

# Target must contain at least one dot (basic domain validation)
if ! [[ "$TARGET" =~ \. ]]; then
    echo "ERROR: Target must be a fully qualified domain name: ${TARGET}" >&2
    exit 2
fi

# Defense-in-depth domain scope validation
source /app/scripts/scope-check.sh
validate_domain_scope "$TARGET"

# Validate passive_only is a boolean string
PASSIVE_ONLY_LOWER=$(echo "$PASSIVE_ONLY" | tr '[:upper:]' '[:lower:]')
if [[ "$PASSIVE_ONLY_LOWER" != "true" ]] && [[ "$PASSIVE_ONLY_LOWER" != "false" ]]; then
    echo "ERROR: passive_only must be 'true' or 'false', got: ${PASSIVE_ONLY}" >&2
    exit 2
fi

# --- Build command ---
AMASS_CMD="amass"
AMASS_ARGS=(
    "enum"
    "-d" "$TARGET"
    "-json" "$OUTPUT_FILE"
)

# Add passive flag if requested
if [[ "$PASSIVE_ONLY_LOWER" == "true" ]]; then
    AMASS_ARGS+=("-passive")
fi

FULL_CMD="${AMASS_CMD} ${AMASS_ARGS[*]}"

# --- Execute ---
echo "AMASS_START scan_id=${SCAN_ID} target=${TARGET} passive_only=${PASSIVE_ONLY_LOWER} timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

START_TIME=$(date +%s%N)

# Run amass with a process timeout as a last-resort safety net
if timeout "$TIMEOUT_SECONDS" $AMASS_CMD "${AMASS_ARGS[@]}" 2>&1 | while IFS= read -r line; do
    echo "[amass] $line" >&2
done; then
    EXIT_CODE=${PIPESTATUS[0]}
else
    EXIT_CODE=${PIPESTATUS[0]}
fi

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "AMASS_END scan_id=${SCAN_ID} exit_code=${EXIT_CODE} duration_ms=${DURATION_MS}" >&2

# --- Return structured JSON to the runtime ---
if [[ $EXIT_CODE -eq 0 ]] && [[ -f "$OUTPUT_FILE" ]]; then
    echo "{\"status\": \"success\", \"output_file\": \"${OUTPUT_FILE}\", \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"amass_enum\", \"command\": \"${FULL_CMD}\"}"
    exit 0
else
    echo "{\"status\": \"error\", \"exit_code\": ${EXIT_CODE}, \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"amass_enum\", \"command\": \"${FULL_CMD}\"}"
    exit 1
fi

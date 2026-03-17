#!/usr/bin/env bash
# =============================================================================
# impacket-wrapper.sh -- Sandboxed Impacket remote execution
#
# This script wraps Impacket's suite of remote execution tools (psexec,
# wmiexec, smbexec, atexec, dcomexec). By the time this runs, the Cedar
# Gate has already authorized the action AND a human operator has approved it.
#
# This wrapper adds:
#   - Argument sanitization (defense in depth beyond the Gate)
#   - Technique validation (only known-good techniques)
#   - Pass-the-hash detection and flag construction
#   - Output capture and structured JSON response
#   - Timing and resource tracking
#
# Called by the Symbiont runtime via the impacket_exec MCP tool.
# =============================================================================

set -euo pipefail
INJECTION_RE='[;&|$`(){}]'

# --- Configuration ---
SCAN_DIR="/app/.symbiont/scans"
TIMEOUT_SECONDS=300

# --- Parse arguments ---
TARGET="${1:?ERROR: Target IP required}"
TECHNIQUE="${2:?ERROR: Technique required (psexec/wmiexec/smbexec/atexec/dcomexec)}"
USERNAME="${3:?ERROR: Username required}"
PASSWORD="${4:?ERROR: Password or hash required}"
DOMAIN="${5:-.}"
COMMAND="${6:?ERROR: Command to execute required}"
SCAN_ID="${7:-$(date +%s)-$$}"

OUTPUT_FILE="${SCAN_DIR}/${SCAN_ID}-impacket.txt"

# --- Ensure output directory exists ---
mkdir -p "$SCAN_DIR"

# --- Argument sanitization (defense in depth) ---

# Block shell injection attempts in target
if [[ "$TARGET" =~ $INJECTION_RE ]]; then
    echo "ERROR: Invalid characters in target: ${TARGET}" >&2
    exit 2
fi

# Block shell injection in username
if [[ "$USERNAME" =~ $INJECTION_RE ]]; then
    echo "ERROR: Invalid characters in username: ${USERNAME}" >&2
    exit 2
fi

# Block shell injection in domain
if [[ "$DOMAIN" =~ $INJECTION_RE ]]; then
    echo "ERROR: Invalid characters in domain: ${DOMAIN}" >&2
    exit 2
fi

# Block shell injection in command (allow common command characters but not shell metacharacters)
if [[ "$COMMAND" =~ [\|\&\$\`] ]]; then
    echo "ERROR: Shell metacharacters not allowed in command: ${COMMAND}" >&2
    exit 2
fi

# Validate target looks like an IP address or hostname
if ! [[ "$TARGET" =~ ^[a-zA-Z0-9._:-]+$ ]]; then
    echo "ERROR: Target must be a valid IP or hostname: ${TARGET}" >&2
    exit 2
fi

# Validate technique
VALID_TECHNIQUES="psexec wmiexec smbexec atexec dcomexec"
if ! echo "$VALID_TECHNIQUES" | grep -qw "$TECHNIQUE"; then
    echo "ERROR: Unknown technique: ${TECHNIQUE}. Must be one of: ${VALID_TECHNIQUES}" >&2
    exit 2
fi

# --- Determine authentication method ---
# If password contains ":" it is treated as LMHASH:NTHASH for pass-the-hash
USE_HASHES=false
HASHES_FLAG=""
AUTH_STRING=""

if [[ "$PASSWORD" == *":"* ]] && [[ ${#PASSWORD} -ge 33 ]]; then
    # Pass-the-hash mode: password is in LM:NT format
    USE_HASHES=true
    HASHES_FLAG="-hashes"
    AUTH_STRING="${DOMAIN}/${USERNAME}@${TARGET}"
else
    # Standard password authentication
    AUTH_STRING="${DOMAIN}/${USERNAME}:${PASSWORD}@${TARGET}"
fi

# --- Build command based on technique ---
IMPACKET_CMD=""
IMPACKET_ARGS=()

case "$TECHNIQUE" in
    psexec)
        IMPACKET_CMD="impacket-psexec"
        ;;
    wmiexec)
        IMPACKET_CMD="impacket-wmiexec"
        ;;
    smbexec)
        IMPACKET_CMD="impacket-smbexec"
        ;;
    atexec)
        IMPACKET_CMD="impacket-atexec"
        ;;
    dcomexec)
        IMPACKET_CMD="impacket-dcomexec"
        ;;
esac

# Add hash flag if using pass-the-hash
if [[ "$USE_HASHES" == true ]]; then
    IMPACKET_ARGS+=("$HASHES_FLAG" "$PASSWORD")
fi

# Add authentication string and command
IMPACKET_ARGS+=("$AUTH_STRING" "$COMMAND")

# --- Execute ---
echo "EXEC_START scan_id=${SCAN_ID} target=${TARGET} technique=${TECHNIQUE} timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

START_TIME=$(date +%s%N)

# Run impacket with timeout, capture stdout+stderr to output file
EXEC_SUCCESS=true
timeout "$TIMEOUT_SECONDS" "$IMPACKET_CMD" "${IMPACKET_ARGS[@]}" > "$OUTPUT_FILE" 2>&1 || EXEC_SUCCESS=false

EXIT_CODE=$?

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "EXEC_END scan_id=${SCAN_ID} exit_code=${EXIT_CODE} duration_ms=${DURATION_MS}" >&2

# --- Build sanitized command string for logging (mask password/hash) ---
if [[ "$USE_HASHES" == true ]]; then
    LOG_CMD="${IMPACKET_CMD} -hashes ***REDACTED*** ${DOMAIN}/${USERNAME}@${TARGET} \"${COMMAND}\""
else
    LOG_CMD="${IMPACKET_CMD} ${DOMAIN}/${USERNAME}:***REDACTED***@${TARGET} \"${COMMAND}\""
fi

# --- Return JSON result ---
if [[ "$EXEC_SUCCESS" == true ]] && [[ -f "$OUTPUT_FILE" ]]; then
    echo "{\"status\": \"success\", \"output_file\": \"${OUTPUT_FILE}\", \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"impacket_exec\", \"command\": \"${LOG_CMD}\", \"technique\": \"${TECHNIQUE}\", \"success\": true}"
    exit 0
else
    echo "{\"status\": \"error\", \"output_file\": \"${OUTPUT_FILE}\", \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"impacket_exec\", \"command\": \"${LOG_CMD}\", \"technique\": \"${TECHNIQUE}\", \"success\": false}"
    exit 1
fi

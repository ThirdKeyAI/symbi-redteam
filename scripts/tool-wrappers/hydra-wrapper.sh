#!/usr/bin/env bash
# =============================================================================
# hydra-wrapper.sh -- Sandboxed THC Hydra execution
#
# This script is the actual "Act" in the ORGA loop. By the time this runs,
# the Cedar Gate has already authorized the brute-force attack AND a human
# operator has approved it via the escalation gate.
#
# This wrapper adds:
#   - Argument sanitization (defense in depth beyond the Gate)
#   - Service validation against an allowed list
#   - Output capture in JSON format for structured parsing
#   - Timing and resource tracking
#   - Clean exit codes for the runtime to interpret
#
# Called by the Symbiont runtime via the hydra_bruteforce MCP tool.
# =============================================================================

set -euo pipefail
INJECTION_RE='[;&|$`(){}]'

# --- Configuration ---
SCAN_DIR="/app/.symbiont/scans"
PARSE_SCRIPT="/app/scripts/parse-outputs/parse-hydra.py"

# --- Parse arguments ---
TARGET="${1:?ERROR: Target IP/hostname required}"
SERVICE="${2:?ERROR: Service protocol required}"
PORT="${3:-0}"
USERNAME_FILE="${4:-}"
PASSWORD_FILE="${5:-}"
USERNAME="${6:-}"
PASSWORD="${7:-}"
THREADS="${8:-4}"
TIMEOUT="${9:-30}"
SCAN_ID="${10:-$(date +%s)-$$}"

OUTPUT_FILE="${SCAN_DIR}/${SCAN_ID}-hydra.json"

# --- Create output directory ---
mkdir -p "$SCAN_DIR"

# --- Argument sanitization (defense in depth) ---
# Block shell injection attempts in all arguments
for argname in TARGET SERVICE PORT USERNAME_FILE PASSWORD_FILE USERNAME PASSWORD THREADS TIMEOUT; do
    argval="${!argname}"
    if [[ "$argval" =~ $INJECTION_RE ]]; then
        echo "ERROR: Invalid characters in ${argname}: ${argval}" >&2
        exit 2
    fi
done

# Block obviously wrong targets
if [[ "$TARGET" == "0.0.0.0" ]] || [[ "$TARGET" == "*" ]]; then
    echo "ERROR: Wildcard/global targets forbidden" >&2
    exit 2
fi

# Validate service is in the allowed list
VALID_SERVICES="ssh ftp http-get http-post-form http-head smb rdp telnet mysql postgres mssql vnc pop3 imap smtp snmp ldap2 ldap3 socks5 adam6500"
if ! echo "$VALID_SERVICES" | grep -qw "$SERVICE"; then
    echo "ERROR: Unknown or disallowed service: ${SERVICE}" >&2
    echo "ERROR: Allowed services: ${VALID_SERVICES}" >&2
    exit 2
fi

# Validate PORT is numeric
if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
    echo "ERROR: Port must be numeric: ${PORT}" >&2
    exit 2
fi

# Validate THREADS is numeric and within bounds
if ! [[ "$THREADS" =~ ^[0-9]+$ ]]; then
    echo "ERROR: Threads must be numeric: ${THREADS}" >&2
    exit 2
fi
if [[ "$THREADS" -gt 64 ]]; then
    echo "WARNING: Clamping threads from ${THREADS} to 64" >&2
    THREADS=64
fi
if [[ "$THREADS" -lt 1 ]]; then
    THREADS=1
fi

# Validate TIMEOUT is numeric
if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]]; then
    echo "ERROR: Timeout must be numeric: ${TIMEOUT}" >&2
    exit 2
fi

# Validate that username/password source files exist if specified
if [[ -n "$USERNAME_FILE" ]] && [[ ! -f "$USERNAME_FILE" ]]; then
    echo "ERROR: Username file not found: ${USERNAME_FILE}" >&2
    exit 2
fi
if [[ -n "$PASSWORD_FILE" ]] && [[ ! -f "$PASSWORD_FILE" ]]; then
    echo "ERROR: Password file not found: ${PASSWORD_FILE}" >&2
    exit 2
fi

# Must have at least one username source
if [[ -z "$USERNAME" ]] && [[ -z "$USERNAME_FILE" ]]; then
    echo "ERROR: Either USERNAME or USERNAME_FILE must be provided" >&2
    exit 2
fi

# Must have at least one password source
if [[ -z "$PASSWORD" ]] && [[ -z "$PASSWORD_FILE" ]]; then
    echo "ERROR: Either PASSWORD or PASSWORD_FILE must be provided" >&2
    exit 2
fi

# --- Build Hydra command ---
HYDRA_CMD="hydra"
HYDRA_ARGS=()

# Username source
if [[ -n "$USERNAME" ]]; then
    HYDRA_ARGS+=(-l "$USERNAME")
elif [[ -n "$USERNAME_FILE" ]]; then
    HYDRA_ARGS+=(-L "$USERNAME_FILE")
fi

# Password source
if [[ -n "$PASSWORD" ]]; then
    HYDRA_ARGS+=(-p "$PASSWORD")
elif [[ -n "$PASSWORD_FILE" ]]; then
    HYDRA_ARGS+=(-P "$PASSWORD_FILE")
fi

# Thread count
HYDRA_ARGS+=(-t "$THREADS")

# Connection timeout
HYDRA_ARGS+=(-w "$TIMEOUT")

# Output file in JSON format
HYDRA_ARGS+=(-o "$OUTPUT_FILE" -b json)

# Port (if not default)
if [[ "$PORT" != "0" ]]; then
    HYDRA_ARGS+=(-s "$PORT")
fi

# Target and service
HYDRA_ARGS+=("${SERVICE}://${TARGET}")

# --- Execute ---
echo "EXPLOIT_START scan_id=${SCAN_ID} target=${TARGET} service=${SERVICE} tool=hydra timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

START_TIME=$(date +%s%N)

# Run hydra with a process timeout (credential testing can take a long time)
FULL_CMD="${HYDRA_CMD} ${HYDRA_ARGS[*]}"
timeout 1800 $HYDRA_CMD "${HYDRA_ARGS[@]}" 2>&1 | while IFS= read -r line; do
    echo "[hydra] $line" >&2
done

EXIT_CODE=${PIPESTATUS[0]}

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "EXPLOIT_END scan_id=${SCAN_ID} exit_code=${EXIT_CODE} duration_ms=${DURATION_MS}" >&2

# --- Count credentials found ---
CREDS_FOUND=0
if [[ -f "$OUTPUT_FILE" ]]; then
    # Parse the Hydra JSON output to count credentials
    if command -v python3 &>/dev/null && [[ -f "$PARSE_SCRIPT" ]]; then
        PARSED=$(python3 "$PARSE_SCRIPT" "$OUTPUT_FILE" 2>/dev/null || true)
        if [[ -n "$PARSED" ]]; then
            CREDS_FOUND=$(echo "$PARSED" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('credentials_found', 0))" 2>/dev/null || echo "0")
        fi
    else
        # Fallback: count results array entries in the JSON
        CREDS_FOUND=$(python3 -c "
import json, sys
try:
    with open('${OUTPUT_FILE}') as f:
        data = json.load(f)
    print(len(data.get('results', [])))
except Exception:
    print(0)
" 2>/dev/null || echo "0")
    fi
fi

# --- Return JSON result to the runtime ---
if [[ $EXIT_CODE -eq 0 ]] || [[ $EXIT_CODE -eq 1 ]]; then
    # Hydra returns 0 on success (found creds) or may return non-zero with partial results
    STATUS="success"
    if [[ $EXIT_CODE -ne 0 ]] && [[ "$CREDS_FOUND" -eq 0 ]]; then
        STATUS="completed_no_credentials"
    fi
    cat <<RESULT_JSON
{"status": "${STATUS}", "output_file": "${OUTPUT_FILE}", "scan_id": "${SCAN_ID}", "duration_ms": ${DURATION_MS}, "tool": "hydra_bruteforce", "command": "${FULL_CMD}", "credentials_found": ${CREDS_FOUND}}
RESULT_JSON
    exit 0
else
    cat <<RESULT_JSON
{"status": "error", "output_file": "${OUTPUT_FILE}", "scan_id": "${SCAN_ID}", "duration_ms": ${DURATION_MS}, "tool": "hydra_bruteforce", "command": "${FULL_CMD}", "credentials_found": 0}
RESULT_JSON
    exit 1
fi

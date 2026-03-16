#!/usr/bin/env bash
# =============================================================================
# msf-wrapper.sh -- Sandboxed Metasploit Framework execution
#
# This script is the actual "Act" in the ORGA loop. By the time this runs,
# the Cedar Gate has already authorized the exploit AND a human operator
# has approved it via the escalation gate.
#
# This wrapper adds:
#   - Argument sanitization (defense in depth beyond the Gate)
#   - Module path validation
#   - Output capture for structured parsing
#   - Session detection from msfconsole output
#   - Timing and resource tracking
#   - Clean exit codes for the runtime to interpret
#
# Called by the Symbiont runtime via the metasploit_run MCP tool.
# =============================================================================

set -euo pipefail

# --- Configuration ---
SCAN_DIR="/app/.symbiont/scans"
PARSE_SCRIPT="/app/scripts/parse-outputs/parse-msf.py"

# --- Parse arguments ---
MODULE="${1:?ERROR: Metasploit module path required}"
TARGET="${2:?ERROR: Target (RHOSTS) required}"
PORT="${3:-0}"
PAYLOAD="${4:?ERROR: Payload module required}"
LHOST="${5:?ERROR: Listener IP (LHOST) required}"
LPORT="${6:-4444}"
OPTIONS="${7:-}"
SCAN_ID="${8:-$(date +%s)-$$}"

OUTPUT_FILE="${SCAN_DIR}/${SCAN_ID}-msf.txt"

# --- Create output directory ---
mkdir -p "$SCAN_DIR"

# --- Argument sanitization (defense in depth) ---
# Block shell injection attempts in all arguments.
# We are especially careful here because these values end up inside an
# msfconsole -x command string.
for argname in MODULE TARGET PORT PAYLOAD LHOST LPORT; do
    argval="${!argname}"
    if [[ "$argval" =~ [\;\|\&\$\`\(\)\{\}\<\>] ]]; then
        echo "ERROR: Invalid characters in ${argname}: ${argval}" >&2
        exit 2
    fi
done

# Validate OPTIONS separately -- it may contain semicolons as delimiters
# but must not contain shell metacharacters
if [[ -n "$OPTIONS" ]]; then
    if [[ "$OPTIONS" =~ [\|\&\$\`\(\)\{\}\<\>] ]]; then
        echo "ERROR: Invalid characters in OPTIONS: ${OPTIONS}" >&2
        exit 2
    fi
    # Validate each option looks like "set KEY VALUE"
    IFS=';' read -ra OPT_PARTS <<< "$OPTIONS"
    for opt in "${OPT_PARTS[@]}"; do
        opt_trimmed=$(echo "$opt" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        if [[ -n "$opt_trimmed" ]] && ! [[ "$opt_trimmed" =~ ^set[[:space:]]+[A-Za-z0-9_]+[[:space:]]+ ]]; then
            echo "ERROR: Invalid option format (expected 'set KEY VALUE'): ${opt_trimmed}" >&2
            exit 2
        fi
    done
fi

# Block obviously wrong targets
if [[ "$TARGET" == "0.0.0.0" ]] || [[ "$TARGET" == "*" ]]; then
    echo "ERROR: Wildcard/global targets forbidden" >&2
    exit 2
fi

# Validate MODULE looks like a valid Metasploit module path
if ! [[ "$MODULE" =~ ^(exploit|auxiliary|post|encoder|nop|evasion)/ ]]; then
    echo "ERROR: Invalid module path (must start with exploit/, auxiliary/, post/, encoder/, nop/, or evasion/): ${MODULE}" >&2
    exit 2
fi

# Validate PORT is numeric
if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
    echo "ERROR: Port must be numeric: ${PORT}" >&2
    exit 2
fi

# Validate LPORT is numeric
if ! [[ "$LPORT" =~ ^[0-9]+$ ]]; then
    echo "ERROR: LPORT must be numeric: ${LPORT}" >&2
    exit 2
fi

# Validate LHOST looks like an IP address or hostname
if ! [[ "$LHOST" =~ ^[A-Za-z0-9\.\:\-]+$ ]]; then
    echo "ERROR: Invalid LHOST format: ${LHOST}" >&2
    exit 2
fi

# --- Build msfconsole command ---
MSF_COMMANDS="use ${MODULE}; set RHOSTS ${TARGET};"

# Set RPORT only if non-zero
if [[ "$PORT" != "0" ]]; then
    MSF_COMMANDS="${MSF_COMMANDS} set RPORT ${PORT};"
fi

MSF_COMMANDS="${MSF_COMMANDS} set PAYLOAD ${PAYLOAD}; set LHOST ${LHOST}; set LPORT ${LPORT};"

# Append extra options if provided
if [[ -n "$OPTIONS" ]]; then
    MSF_COMMANDS="${MSF_COMMANDS} ${OPTIONS};"
fi

MSF_COMMANDS="${MSF_COMMANDS} run; exit"

# --- Execute ---
echo "EXPLOIT_START scan_id=${SCAN_ID} target=${TARGET} module=${MODULE} tool=msfconsole timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

START_TIME=$(date +%s%N)

# Run msfconsole with a process timeout
# -q = quiet mode (no banner), -x = execute commands, -o = output file
timeout 900 msfconsole -q -x "$MSF_COMMANDS" -o "$OUTPUT_FILE" 2>&1 | while IFS= read -r line; do
    echo "[msf] $line" >&2
done

EXIT_CODE=${PIPESTATUS[0]}

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "EXPLOIT_END scan_id=${SCAN_ID} exit_code=${EXIT_CODE} duration_ms=${DURATION_MS}" >&2

# --- Parse output for session information ---
SESSION_OPENED="false"
SESSION_TYPE="none"

if [[ -f "$OUTPUT_FILE" ]]; then
    # Use the parser script if available
    if command -v python3 &>/dev/null && [[ -f "$PARSE_SCRIPT" ]]; then
        PARSED=$(python3 "$PARSE_SCRIPT" "$OUTPUT_FILE" 2>/dev/null || true)
        if [[ -n "$PARSED" ]]; then
            SESSION_OPENED=$(echo "$PARSED" | python3 -c "import sys, json; d=json.load(sys.stdin); print('true' if d.get('success', False) else 'false')" 2>/dev/null || echo "false")
            SESSION_TYPE=$(echo "$PARSED" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('session_type', 'none'))" 2>/dev/null || echo "none")
        fi
    else
        # Fallback: grep for session indicators in the output
        if grep -qiE "session [0-9]+ opened|meterpreter session" "$OUTPUT_FILE" 2>/dev/null; then
            SESSION_OPENED="true"
            if grep -qiE "meterpreter" "$OUTPUT_FILE" 2>/dev/null; then
                SESSION_TYPE="meterpreter"
            elif grep -qiE "command shell" "$OUTPUT_FILE" 2>/dev/null; then
                SESSION_TYPE="shell"
            else
                SESSION_TYPE="unknown"
            fi
        fi
    fi
fi

# --- Return JSON result to the runtime ---
FULL_CMD="msfconsole -q -x \"${MSF_COMMANDS}\""

if [[ $EXIT_CODE -eq 0 ]]; then
    cat <<RESULT_JSON
{"status": "success", "output_file": "${OUTPUT_FILE}", "scan_id": "${SCAN_ID}", "duration_ms": ${DURATION_MS}, "tool": "metasploit_run", "command": "${FULL_CMD}", "session_opened": ${SESSION_OPENED}, "session_type": "${SESSION_TYPE}"}
RESULT_JSON
    exit 0
else
    cat <<RESULT_JSON
{"status": "error", "output_file": "${OUTPUT_FILE}", "scan_id": "${SCAN_ID}", "duration_ms": ${DURATION_MS}, "tool": "metasploit_run", "command": "${FULL_CMD}", "session_opened": ${SESSION_OPENED}, "session_type": "${SESSION_TYPE}"}
RESULT_JSON
    exit 1
fi

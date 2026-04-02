#!/usr/bin/env bash
# =============================================================================
# nmap-wrapper.sh -- Sandboxed nmap execution
#
# This script is the actual "Act" in the ORGA loop. By the time this runs,
# the Cedar Gate has already authorized the scan. This wrapper adds:
#   - Argument sanitization (defense in depth beyond the Gate)
#   - Output capture in XML format for structured parsing
#   - Timing and resource tracking
#   - Clean exit codes for the runtime to interpret
#
# Called by the Symbiont runtime via the nmap_scan MCP tool.
# =============================================================================

set -euo pipefail
INJECTION_RE='[;&|$`(){}]'

# --- Configuration ---
SCAN_DIR="/app/.symbiont/scans"
MAX_RATE="${NMAP_MAX_RATE:-1000}"
DEFAULT_TIMING="${NMAP_DEFAULT_TIMING:-T3}"

# --- Parse arguments ---
TARGET="${1:?ERROR: Target CIDR required}"
SCAN_TYPE="${2:?ERROR: Scan type required}"
SCAN_ID="${3:-$(date +%s)-$$}"

OUTPUT_FILE="${SCAN_DIR}/${SCAN_ID}.xml"

# --- Argument sanitization (defense in depth) ---
# Even though Cedar authorized this scan, we validate arguments here
# to protect against bugs in the Cedar policy or runtime.

# Block shell injection attempts in target
if [[ "$TARGET" =~ $INJECTION_RE ]]; then
    echo "ERROR: Invalid characters in target: ${TARGET}" >&2
    exit 2
fi

# Block obviously wrong targets
if [[ "$TARGET" == "0.0.0.0/0" ]] || [[ "$TARGET" == "*" ]]; then
    echo "ERROR: Wildcard/global targets forbidden" >&2
    exit 2
fi

# Defense-in-depth scope validation
source /app/scripts/scope-check.sh
validate_scope "$TARGET"

# Validate scan type
VALID_TYPES="ping service version syn os_detect aggressive vuln_script"
if ! echo "$VALID_TYPES" | grep -qw "$SCAN_TYPE"; then
    echo "ERROR: Unknown scan type: ${SCAN_TYPE}" >&2
    exit 2
fi

# --- Build nmap command based on scan type ---
NMAP_CMD="nmap"
NMAP_ARGS=()

case "$SCAN_TYPE" in
    ping)
        # ICMP ping sweep -- minimal footprint
        NMAP_ARGS+=(-sn -PE)
        ;;
    service)
        # TCP connect scan with service detection
        NMAP_ARGS+=(-sT -sV --version-intensity 5)
        ;;
    version)
        # Version detection on common ports
        NMAP_ARGS+=(-sV --version-all --top-ports 1000)
        ;;
    syn)
        # SYN scan (requires CAP_NET_RAW)
        NMAP_ARGS+=(-sS --top-ports 1000)
        ;;
    os_detect)
        # OS fingerprinting (requires human approval via escalation.cedar)
        NMAP_ARGS+=(-sS -O --osscan-guess)
        ;;
    aggressive)
        # Aggressive scan (requires human approval + incident_response mode)
        NMAP_ARGS+=(-A -T4 --top-ports 10000)
        ;;
    vuln_script)
        # Vulnerability scripts (requires human approval + incident_response)
        NMAP_ARGS+=(-sV --script=vuln --script-timeout 60s)
        ;;
esac

# Common flags
NMAP_ARGS+=(
    -"${DEFAULT_TIMING}"        # Timing template
    --max-rate "$MAX_RATE"      # Packet rate limit
    -oX "$OUTPUT_FILE"          # XML output for structured parsing
    --no-stylesheet             # Skip XSLT (we parse raw XML)
    -v                          # Verbose for logging
)

# Target goes last
NMAP_ARGS+=("$TARGET")

# --- Execute ---
echo "SCAN_START scan_id=${SCAN_ID} target=${TARGET} type=${SCAN_TYPE} timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

START_TIME=$(date +%s%N)

# Run nmap with a process timeout as a last-resort safety net
timeout 300 $NMAP_CMD "${NMAP_ARGS[@]}" 2>&1 | while IFS= read -r line; do
    echo "[nmap] $line" >&2
done

EXIT_CODE=${PIPESTATUS[0]}

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "SCAN_END scan_id=${SCAN_ID} exit_code=${EXIT_CODE} duration_ms=${DURATION_MS}" >&2

# --- Return output file path to the runtime ---
FULL_CMD="${NMAP_CMD} ${NMAP_ARGS[*]}"

if [[ $EXIT_CODE -eq 0 ]] && [[ -f "$OUTPUT_FILE" ]]; then
    echo "{\"status\": \"success\", \"output_file\": \"${OUTPUT_FILE}\", \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"nmap_scan\", \"command\": \"${FULL_CMD}\"}"
    exit 0
else
    echo "{\"status\": \"error\", \"exit_code\": ${EXIT_CODE}, \"scan_id\": \"${SCAN_ID}\", \"tool\": \"nmap_scan\", \"command\": \"${FULL_CMD}\"}"
    exit 1
fi

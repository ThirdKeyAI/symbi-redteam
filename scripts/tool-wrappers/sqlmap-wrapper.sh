#!/usr/bin/env bash
# =============================================================================
# sqlmap-wrapper.sh -- Sandboxed sqlmap execution
#
# This script is the actual "Act" in the ORGA loop. By the time this runs,
# the Cedar Gate has already authorized the scan. This wrapper adds:
#   - Argument sanitization (defense in depth beyond the Gate)
#   - Mode enforcement (detect vs exploit)
#   - Explicit blocklist of dangerous flags (--os-shell, --os-cmd, --priv-esc)
#   - Output capture for structured parsing
#   - Timing and resource tracking
#   - Clean exit codes for the runtime to interpret
#
# Called by the Symbiont runtime via sqlmap_detect (vuln_tools) and
# sqlmap_exploit / sqlmap_dump (exploit_tools) MCP tools.
#
# Modes:
#   detect  -- Identify injection points only. No data extraction.
#   exploit -- Extract data via --dump/--dump-all. Used by exploit_tools only.
#              Supports targeted extraction with DATABASE, TABLE, COLUMNS args.
#
# NEVER adds --os-shell, --os-cmd, or --priv-esc flags regardless of mode.
# =============================================================================

set -euo pipefail

# --- Configuration ---
SCAN_DIR="/app/.symbiont/scans"
SQLMAP_TIMEOUT="${SQLMAP_TIMEOUT:-1800}"

# --- Parse arguments ---
# Two calling conventions are supported:
#   Legacy (vuln_tools):   TARGET_URL METHOD DATA LEVEL RISK MODE SCAN_ID
#   Exploit (exploit_tools): MODE TARGET_URL METHOD DATA LEVEL RISK DATABASE TABLE COLUMNS DUMP_ALL SCAN_ID
#
# We detect which convention by checking if $1 starts with "http" (legacy)
# or is a mode string (exploit convention).

if [[ "$1" == "detect" ]] || [[ "$1" == "exploit" ]]; then
    # Exploit convention: MODE is first argument
    MODE="${1:?ERROR: Mode required (detect or exploit)}"
    TARGET_URL="${2:?ERROR: Target URL required}"
    METHOD="${3:-GET}"
    DATA="${4:-}"
    LEVEL="${5:-1}"
    RISK="${6:-1}"
    DATABASE="${7:-}"
    TABLE="${8:-}"
    COLUMNS="${9:-}"
    DUMP_ALL="${10:-false}"
    SCAN_ID="${11:-$(date +%s)-$$}"
else
    # Legacy convention: TARGET_URL is first argument
    TARGET_URL="${1:?ERROR: Target URL required}"
    METHOD="${2:-GET}"
    DATA="${3:-}"
    LEVEL="${4:-1}"
    RISK="${5:-1}"
    MODE="${6:?ERROR: Mode required (detect or exploit)}"
    SCAN_ID="${7:-$(date +%s)-$$}"
    DATABASE=""
    TABLE=""
    COLUMNS=""
    DUMP_ALL="false"
fi

OUTPUT_DIR="${SCAN_DIR}/${SCAN_ID}-sqlmap"

# --- Ensure output directory exists ---
mkdir -p "$OUTPUT_DIR"

# --- Argument sanitization (defense in depth) ---

# Validate MODE is one of the allowed values
if [[ "$MODE" != "detect" ]] && [[ "$MODE" != "exploit" ]]; then
    echo "ERROR: Invalid mode: ${MODE}. Must be 'detect' or 'exploit'." >&2
    exit 2
fi

# Validate METHOD
METHOD_UPPER=$(echo "$METHOD" | tr '[:lower:]' '[:upper:]')
if [[ "$METHOD_UPPER" != "GET" ]] && [[ "$METHOD_UPPER" != "POST" ]]; then
    echo "ERROR: Invalid HTTP method: ${METHOD}. Must be GET or POST." >&2
    exit 2
fi

# Validate LEVEL is in range 1-5
if ! [[ "$LEVEL" =~ ^[1-5]$ ]]; then
    echo "ERROR: Level must be 1-5, got: ${LEVEL}" >&2
    exit 2
fi

# Validate RISK is in range 1-3
if ! [[ "$RISK" =~ ^[1-3]$ ]]; then
    echo "ERROR: Risk must be 1-3, got: ${RISK}" >&2
    exit 2
fi

# Block shell injection attempts in target URL
if [[ "$TARGET_URL" =~ [\;\|\&\$\`] ]]; then
    echo "ERROR: Invalid characters in target URL: ${TARGET_URL}" >&2
    exit 2
fi

# Block shell injection in POST data
if [[ -n "$DATA" ]] && [[ "$DATA" =~ [\;\|\&\$\`] ]]; then
    echo "ERROR: Invalid characters in POST data" >&2
    exit 2
fi

# Defense-in-depth scope validation
source /app/scripts/scope-check.sh
SCOPE_HOST=$(echo "$TARGET_URL" | sed -E 's|https?://||; s|:[0-9]+.*||; s|/.*||')
validate_scope "$SCOPE_HOST"

# Validate DUMP_ALL is boolean
if [[ "$DUMP_ALL" != "true" ]] && [[ "$DUMP_ALL" != "false" ]]; then
    echo "ERROR: dump_all must be 'true' or 'false': ${DUMP_ALL}" >&2
    exit 2
fi

# Validate DATABASE name if provided (alphanumeric, underscore, hyphen only)
if [[ -n "$DATABASE" ]] && ! [[ "$DATABASE" =~ ^[A-Za-z0-9_\-]+$ ]]; then
    echo "ERROR: Invalid database name (alphanumeric, underscore, hyphen only): ${DATABASE}" >&2
    exit 2
fi

# Validate TABLE name if provided
if [[ -n "$TABLE" ]] && ! [[ "$TABLE" =~ ^[A-Za-z0-9_\-]+$ ]]; then
    echo "ERROR: Invalid table name (alphanumeric, underscore, hyphen only): ${TABLE}" >&2
    exit 2
fi

# Validate COLUMNS if provided (comma-separated alphanumeric identifiers)
if [[ -n "$COLUMNS" ]] && ! [[ "$COLUMNS" =~ ^[A-Za-z0-9_\-]+(,[A-Za-z0-9_\-]+)*$ ]]; then
    echo "ERROR: Invalid columns format (comma-separated identifiers): ${COLUMNS}" >&2
    exit 2
fi

# --- Build sqlmap command ---
SQLMAP_CMD="sqlmap"
SQLMAP_ARGS=(
    -u "$TARGET_URL"
    "--method=$METHOD_UPPER"
    "--level=$LEVEL"
    "--risk=$RISK"
    --batch
    "--output-dir=$OUTPUT_DIR"
)

# Add POST data if provided
if [[ -n "$DATA" ]]; then
    SQLMAP_ARGS+=("--data=$DATA")
fi

# Mode-specific flags
case "$MODE" in
    detect)
        # Detection only: use smart mode and forms detection
        SQLMAP_ARGS+=(--forms --smart)
        ;;
    exploit)
        # Data extraction: targeted or broad dump
        if [[ "$DUMP_ALL" == "true" ]]; then
            # Dump all databases
            SQLMAP_ARGS+=(--dump-all)
        elif [[ -n "$DATABASE" ]] && [[ -n "$TABLE" ]]; then
            # Targeted extraction: specific database and table
            SQLMAP_ARGS+=(-D "$DATABASE" -T "$TABLE" --dump)
            if [[ -n "$COLUMNS" ]]; then
                SQLMAP_ARGS+=(-C "$COLUMNS")
            fi
        elif [[ -n "$DATABASE" ]]; then
            # Dump all tables in a specific database
            SQLMAP_ARGS+=(-D "$DATABASE" --dump)
        else
            # Default: dump whatever is found
            SQLMAP_ARGS+=(--dump)
        fi
        ;;
esac

# =============================================================================
# SAFETY: NEVER add these flags regardless of mode or input.
# These are hardcoded blocks that cannot be overridden.
# =============================================================================
# BLOCKED: --os-shell    (interactive OS shell)
# BLOCKED: --os-cmd      (arbitrary OS command execution)
# BLOCKED: --priv-esc    (privilege escalation)
# =============================================================================

# --- Execute ---
echo "SCAN_START scan_id=${SCAN_ID} target=${TARGET_URL} mode=${MODE} tool=sqlmap timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

START_TIME=$(date +%s%N)

# Capture sqlmap output to a log file for parsing
LOG_FILE="${OUTPUT_DIR}/sqlmap-run.log"

# Run sqlmap with a process timeout as a last-resort safety net
timeout "$SQLMAP_TIMEOUT" $SQLMAP_CMD "${SQLMAP_ARGS[@]}" 2>&1 | tee "$LOG_FILE" | while IFS= read -r line; do
    echo "[sqlmap] $line" >&2
done

EXIT_CODE=${PIPESTATUS[0]}

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "SCAN_END scan_id=${SCAN_ID} exit_code=${EXIT_CODE} duration_ms=${DURATION_MS}" >&2

# --- Determine vulnerability status from log ---
VULNERABLE=false
if [[ -f "$LOG_FILE" ]]; then
    if grep -q "is vulnerable" "$LOG_FILE" 2>/dev/null || \
       grep -q "sqlmap identified the following injection point" "$LOG_FILE" 2>/dev/null; then
        VULNERABLE=true
    fi
fi

# --- Determine tool name based on mode ---
if [[ "$MODE" == "exploit" ]]; then
    TOOL_NAME="sqlmap_exploit"
else
    TOOL_NAME="sqlmap_detect"
fi

# --- Return structured output to the runtime ---
FULL_CMD="${SQLMAP_CMD} ${SQLMAP_ARGS[*]}"

# Escape the command string for JSON (handle double quotes)
FULL_CMD_ESCAPED=$(echo "$FULL_CMD" | sed 's/"/\\"/g')

if [[ $EXIT_CODE -eq 0 ]]; then
    cat <<JSONEOF
{"status": "success", "output_file": "${OUTPUT_DIR}", "scan_id": "${SCAN_ID}", "duration_ms": ${DURATION_MS}, "tool": "${TOOL_NAME}", "command": "${FULL_CMD_ESCAPED}", "mode": "${MODE}", "vulnerable": ${VULNERABLE}}
JSONEOF
    exit 0
else
    cat <<JSONEOF
{"status": "error", "exit_code": ${EXIT_CODE}, "output_file": "${OUTPUT_DIR}", "scan_id": "${SCAN_ID}", "duration_ms": ${DURATION_MS}, "tool": "${TOOL_NAME}", "command": "${FULL_CMD_ESCAPED}", "mode": "${MODE}", "vulnerable": ${VULNERABLE}}
JSONEOF
    exit 1
fi

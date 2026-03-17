#!/usr/bin/env bash
# =============================================================================
# whatweb-wrapper.sh -- Sandboxed WhatWeb execution
#
# Performs web technology fingerprinting against a target URL. By the time this
# runs, the Cedar Gate has already authorized the scan. This wrapper adds:
#   - Argument sanitization (defense in depth beyond the Gate)
#   - Output capture in JSON format for structured parsing
#   - Timing and resource tracking
#   - Clean exit codes for the runtime to interpret
#
# Called by the Symbiont runtime via the whatweb_scan MCP tool.
# =============================================================================

set -euo pipefail
INJECTION_RE='[;&|$`(){}]'

# --- Configuration ---
SCAN_DIR="/app/.symbiont/scans"
TIMEOUT_SECONDS="${WHATWEB_TIMEOUT:-120}"

# --- Parse arguments ---
TARGET="${1:?ERROR: Target URL required}"
AGGRESSION_LEVEL="${2:-1}"
SCAN_ID="${3:-$(date +%s)-$$}"

OUTPUT_FILE="${SCAN_DIR}/${SCAN_ID}-whatweb.json"

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

# Target must look like a URL or domain
if ! [[ "$TARGET" =~ ^[a-zA-Z0-9._:/%@?=\&+,-]+$ ]]; then
    echo "ERROR: Target does not look like a valid URL: ${TARGET}" >&2
    exit 2
fi

# Validate aggression level is 1-4
if ! [[ "$AGGRESSION_LEVEL" =~ ^[1-4]$ ]]; then
    echo "ERROR: Aggression level must be 1-4, got: ${AGGRESSION_LEVEL}" >&2
    exit 2
fi

# --- Build command ---
WHATWEB_CMD="whatweb"
WHATWEB_ARGS=(
    "--color=never"
    "-a" "$AGGRESSION_LEVEL"
    "--log-json=${OUTPUT_FILE}"
    "$TARGET"
)

FULL_CMD="${WHATWEB_CMD} ${WHATWEB_ARGS[*]}"

# --- Execute ---
echo "WHATWEB_START scan_id=${SCAN_ID} target=${TARGET} aggression=${AGGRESSION_LEVEL} timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

START_TIME=$(date +%s%N)

# Run whatweb with a process timeout as a last-resort safety net
if timeout "$TIMEOUT_SECONDS" $WHATWEB_CMD "${WHATWEB_ARGS[@]}" >/dev/null 2>&1; then
    EXIT_CODE=0
else
    EXIT_CODE=$?
fi

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "WHATWEB_END scan_id=${SCAN_ID} exit_code=${EXIT_CODE} duration_ms=${DURATION_MS}" >&2

# --- Return structured JSON to the runtime ---
if [[ $EXIT_CODE -eq 0 ]] && [[ -f "$OUTPUT_FILE" ]]; then
    echo "{\"status\": \"success\", \"output_file\": \"${OUTPUT_FILE}\", \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"whatweb_scan\", \"command\": \"${FULL_CMD}\"}"
    exit 0
else
    echo "{\"status\": \"error\", \"exit_code\": ${EXIT_CODE}, \"scan_id\": \"${SCAN_ID}\", \"duration_ms\": ${DURATION_MS}, \"tool\": \"whatweb_scan\", \"command\": \"${FULL_CMD}\"}"
    exit 1
fi

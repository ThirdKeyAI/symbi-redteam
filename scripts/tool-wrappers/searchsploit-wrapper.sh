#!/usr/bin/env bash
# =============================================================================
# searchsploit-wrapper.sh -- Exploit-DB offline database search
#
# This script wraps the searchsploit CLI tool for the ORGA framework.
# No Cedar policy gate is needed -- this is a purely local, read-only
# operation against the Exploit-DB database.
#
# This wrapper adds:
#   - Argument sanitization
#   - JSON output normalization
#   - Timing tracking
#   - Clean exit codes for the runtime to interpret
#
# Called by the Symbiont runtime via the searchsploit_query MCP tool.
# =============================================================================

set -euo pipefail

# --- Configuration ---
SEARCHSPLOIT_TIMEOUT="${SEARCHSPLOIT_TIMEOUT:-30}"

# --- Parse arguments ---
QUERY="${1:?ERROR: Search query required}"
EXACT="${2:-false}"
SCAN_ID="${3:-$(date +%s)-$$}"

# --- Argument sanitization (defense in depth) ---

# Block shell injection attempts in query
if [[ "$QUERY" =~ [\;\|\&\$\`\(\)] ]]; then
    echo "ERROR: Invalid characters in query: ${QUERY}" >&2
    exit 2
fi

# Validate EXACT is boolean
if [[ "$EXACT" != "true" ]] && [[ "$EXACT" != "false" ]]; then
    echo "ERROR: Exact must be 'true' or 'false', got: ${EXACT}" >&2
    exit 2
fi

# --- Build searchsploit command ---
SEARCHSPLOIT_CMD="searchsploit"
SEARCHSPLOIT_ARGS=(--json)

if [[ "$EXACT" == "true" ]]; then
    SEARCHSPLOIT_ARGS+=(--exact)
fi

# Add query terms (split by spaces to pass as separate args)
# shellcheck disable=SC2086
SEARCHSPLOIT_ARGS+=($QUERY)

# --- Execute ---
echo "SEARCH_START scan_id=${SCAN_ID} query='${QUERY}' exact=${EXACT} timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

START_TIME=$(date +%s%N)

# Run searchsploit with a timeout (should be fast -- offline DB)
RAW_OUTPUT=$(timeout "$SEARCHSPLOIT_TIMEOUT" $SEARCHSPLOIT_CMD "${SEARCHSPLOIT_ARGS[@]}" 2>/dev/null) || true

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "SEARCH_END scan_id=${SCAN_ID} duration_ms=${DURATION_MS}" >&2

# --- Parse and normalize the output ---
# searchsploit --json outputs: {"RESULTS_EXPLOIT": [...], "RESULTS_SHELLCODE": [...]}
# We normalize this into a flat exploits list.

FULL_CMD="${SEARCHSPLOIT_CMD} ${SEARCHSPLOIT_ARGS[*]}"

if [[ -z "$RAW_OUTPUT" ]]; then
    # No output -- either error or no results
    cat <<JSONEOF
{"status": "success", "scan_id": "${SCAN_ID}", "duration_ms": ${DURATION_MS}, "tool": "searchsploit_query", "command": "${FULL_CMD}", "exploits": []}
JSONEOF
    exit 0
fi

# Use python3 to normalize the JSON output into our format
NORMALIZED=$(python3 -c "
import json
import sys

try:
    raw = json.loads(sys.stdin.read())
except json.JSONDecodeError:
    print(json.dumps([]))
    sys.exit(0)

exploits = []

# Parse exploit results
for entry in raw.get('RESULTS_EXPLOIT', []):
    exploits.append({
        'title': entry.get('Title', ''),
        'path': entry.get('Path', ''),
        'type': entry.get('Type', 'exploit'),
        'platform': entry.get('Platform', ''),
    })

# Parse shellcode results
for entry in raw.get('RESULTS_SHELLCODE', []):
    exploits.append({
        'title': entry.get('Title', ''),
        'path': entry.get('Path', ''),
        'type': 'shellcode',
        'platform': entry.get('Platform', ''),
    })

print(json.dumps(exploits))
" <<< "$RAW_OUTPUT")

EXPLOITS_COUNT=$(python3 -c "import json,sys; print(len(json.loads(sys.stdin.read())))" <<< "$NORMALIZED")

# Escape the command for JSON
FULL_CMD_ESCAPED=$(echo "$FULL_CMD" | sed 's/"/\\"/g')

# Build the final JSON output using python3 for safe JSON construction
python3 -c "
import json
import sys

exploits = json.loads(sys.argv[1])
result = {
    'status': 'success',
    'scan_id': sys.argv[2],
    'duration_ms': int(sys.argv[3]),
    'tool': 'searchsploit_query',
    'command': sys.argv[4],
    'exploits': exploits,
}
print(json.dumps(result))
" "$NORMALIZED" "$SCAN_ID" "$DURATION_MS" "$FULL_CMD"

exit 0

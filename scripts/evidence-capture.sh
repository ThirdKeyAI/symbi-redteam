#!/usr/bin/env bash
# =============================================================================
# evidence-capture.sh -- Screenshot and output archival utility
#
# Captures evidence artifacts (tool outputs, screenshots, etc.) and stores
# them in the engagement's evidence directory with SHA-256 integrity hashes.
#
# Usage:
#   evidence-capture.sh <engagement_id> <source_path> [description]
#
# Output: JSON with evidence_path, sha256_hash, size_bytes
# =============================================================================

set -euo pipefail
INJECTION_RE='[;&|$`(){}]'

ENGAGEMENT_ID="${1:?ERROR: Engagement ID required}"
SOURCE_PATH="${2:?ERROR: Source file path required}"
DESCRIPTION="${3:-}"

EVIDENCE_BASE="/app/.symbiont/evidence"
EVIDENCE_DIR="${EVIDENCE_BASE}/${ENGAGEMENT_ID}"

# --- Argument validation ---
if [[ "$ENGAGEMENT_ID" =~ $INJECTION_RE ]]; then
    echo '{"status": "error", "message": "Invalid engagement ID"}' >&2
    exit 2
fi

if [[ ! -f "$SOURCE_PATH" ]]; then
    echo "{\"status\": \"error\", \"message\": \"Source file not found: ${SOURCE_PATH}\"}"
    exit 1
fi

# --- Create evidence directory ---
mkdir -p "$EVIDENCE_DIR"

# --- Compute SHA-256 hash ---
SHA256=$(sha256sum "$SOURCE_PATH" | awk '{print $1}')

# --- Get file size ---
SIZE_BYTES=$(stat -c %s "$SOURCE_PATH" 2>/dev/null || stat -f %z "$SOURCE_PATH" 2>/dev/null || echo "0")

# --- Generate evidence filename with hash prefix ---
SOURCE_NAME=$(basename "$SOURCE_PATH")
EVIDENCE_FILE="${SHA256:0:8}_${SOURCE_NAME}"
EVIDENCE_PATH="${EVIDENCE_DIR}/${EVIDENCE_FILE}"

# --- Copy to evidence directory ---
cp "$SOURCE_PATH" "$EVIDENCE_PATH"

# --- Write metadata file alongside evidence ---
METADATA_PATH="${EVIDENCE_PATH}.meta.json"
cat > "$METADATA_PATH" <<METAEOF
{
    "engagement_id": "${ENGAGEMENT_ID}",
    "source_path": "${SOURCE_PATH}",
    "evidence_path": "${EVIDENCE_PATH}",
    "sha256_hash": "${SHA256}",
    "size_bytes": ${SIZE_BYTES},
    "description": "${DESCRIPTION}",
    "captured_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
METAEOF

# --- Return JSON result ---
echo "{\"status\": \"captured\", \"evidence_path\": \"${EVIDENCE_PATH}\", \"sha256_hash\": \"${SHA256}\", \"size_bytes\": ${SIZE_BYTES}}"

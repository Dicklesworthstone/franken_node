#!/usr/bin/env bash
# transplant/resync.sh — Re-sync transplant snapshot from upstream source
#
# Usage: ./transplant/resync.sh [--dry-run] [--source PATH] [--json]
#
# Workflow:
#   1. Run drift detection against upstream source
#   2. If drift found, copy changed/missing files from upstream
#   3. Regenerate lockfile
#   4. Verify new lockfile
#   5. Emit re-sync evidence report
#
# Exit codes:
#   0 = SUCCESS (re-sync completed or no drift)
#   1 = FAIL (verification failed after re-sync)
#   2 = ERROR (prerequisites missing)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCKFILE="${SCRIPT_DIR}/TRANSPLANT_LOCKFILE.sha256"
SNAPSHOT_DIR="${SCRIPT_DIR}/pi_agent_rust"
SOURCE_ROOT="/data/projects/pi_agent_rust"

DRY_RUN=false
JSON_OUTPUT=false

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --json) JSON_OUTPUT=true; shift ;;
    --source) SOURCE_ROOT="$2"; shift 2 ;;
    --help|-h)
      echo "Usage: $0 [--dry-run] [--source PATH] [--json]"
      echo "  --dry-run  Preview changes without modifying files"
      echo "  --source   Override upstream source path"
      echo "  --json     Output structured JSON report"
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

emit_resync_error() {
  local message="$1"
  local error_code="${2:-RESYNC_ERROR}"

  if $JSON_OUTPUT; then
    cat <<ENDJSON
{
  "verdict": "ERROR",
  "timestamp": "$TIMESTAMP",
  "error": {
    "code": "$error_code",
    "message": "$message"
  },
  "source_root": "$SOURCE_ROOT",
  "snapshot_dir": "$SNAPSHOT_DIR"
}
ENDJSON
  else
    echo "ERROR: $message" >&2
  fi

  exit 2
}

parse_json_verdict() {
  printf '%s' "$1" | python3 -c '
import json
import sys

try:
    payload = json.load(sys.stdin)
except Exception:
    print("ERROR")
    raise SystemExit(0)

verdict = payload.get("verdict")
print(verdict if isinstance(verdict, str) else "ERROR")
'
}

extract_drift_list() {
  local report="$1"
  local key="$2"
  printf '%s' "$report" | python3 -c '
import json
import sys

key = sys.argv[1]

try:
    payload = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)

details = payload.get("details") or {}
items = details.get(key) or []
if isinstance(items, list):
    for item in items:
        if isinstance(item, str):
            print(item)
' "$key"
}

echo "=== Transplant Re-sync Workflow ===" >&2
echo "Timestamp: $TIMESTAMP" >&2
echo "Source:    $SOURCE_ROOT" >&2
echo "Snapshot:  $SNAPSHOT_DIR" >&2
echo "Dry-run:   $DRY_RUN" >&2
echo "" >&2

# Step 1: Run drift detection
echo "[1/5] Running drift detection..." >&2
set +e
DRIFT_REPORT=$("$SCRIPT_DIR/drift_detect.sh" --json --quiet --source "$SOURCE_ROOT" 2>/dev/null)
DRIFT_RC=$?
set -e
DRIFT_VERDICT=$(parse_json_verdict "$DRIFT_REPORT")

if [ "$DRIFT_RC" -eq 2 ] || [ "$DRIFT_VERDICT" = "ERROR" ] || [ "$DRIFT_VERDICT" = "UNKNOWN" ]; then
  emit_resync_error "drift detection failed (expected JSON verdict from drift_detect.sh)" "RESYNC_DRIFT_PROBE_FAILED"
fi

if [ "$DRIFT_VERDICT" = "NO_DRIFT" ]; then
  echo "No drift detected. Snapshot is in sync with upstream." >&2
  if $JSON_OUTPUT; then
    echo "{\"verdict\":\"NO_DRIFT\",\"timestamp\":\"$TIMESTAMP\",\"actions\":[]}"
  fi
  exit 0
fi

echo "Drift detected. Analyzing changes..." >&2

# Step 2: Parse drift details
CONTENT_DRIFT=$(extract_drift_list "$DRIFT_REPORT" "content_drift")
MISSING_LOCAL=$(extract_drift_list "$DRIFT_REPORT" "missing_local")
EXTRA_LOCAL=$(extract_drift_list "$DRIFT_REPORT" "extra_local")

ACTIONS=()

# Step 3: Apply changes (or preview)
echo "[2/5] Applying re-sync actions..." >&2

# Copy drifted files from upstream
while IFS= read -r relpath; do
  [ -z "$relpath" ] && continue
  src="${SOURCE_ROOT}/${relpath}"
  dst="${SNAPSHOT_DIR}/${relpath}"
  if $DRY_RUN; then
    echo "  [DRY-RUN] Would update: $relpath" >&2
  else
    dstdir=$(dirname "$dst")
    mkdir -p "$dstdir"
    cp "$src" "$dst"
    echo "  Updated: $relpath" >&2
  fi
  ACTIONS+=("update:$relpath")
done <<< "$CONTENT_DRIFT"

# Restore missing local files from upstream
while IFS= read -r relpath; do
  [ -z "$relpath" ] && continue
  src="${SOURCE_ROOT}/${relpath}"
  dst="${SNAPSHOT_DIR}/${relpath}"
  if [ -f "$src" ]; then
    if $DRY_RUN; then
      echo "  [DRY-RUN] Would restore: $relpath" >&2
    else
      dstdir=$(dirname "$dst")
      mkdir -p "$dstdir"
      cp "$src" "$dst"
      echo "  Restored: $relpath" >&2
    fi
    ACTIONS+=("restore:$relpath")
  fi
done <<< "$MISSING_LOCAL"

# Flag extra local files (do not auto-delete for safety)
while IFS= read -r relpath; do
  [ -z "$relpath" ] && continue
  echo "  WARNING: Extra local file (not auto-removed): $relpath" >&2
  ACTIONS+=("flag_extra:$relpath")
done <<< "$EXTRA_LOCAL"

if $DRY_RUN; then
  echo "" >&2
  echo "[DRY-RUN] No files modified. Re-run without --dry-run to apply." >&2
  ACTION_COUNT=${#ACTIONS[@]}
  if $JSON_OUTPUT; then
    echo "{\"verdict\":\"DRY_RUN\",\"timestamp\":\"$TIMESTAMP\",\"planned_actions\":$ACTION_COUNT}"
  fi
  exit 0
fi

# Step 4: Regenerate lockfile
echo "[3/5] Regenerating lockfile..." >&2
"$SCRIPT_DIR/generate_lockfile.sh" --source-root "$SOURCE_ROOT" 2>&1 | sed 's/^/  /' >&2

# Step 5: Verify new lockfile
echo "[4/5] Verifying new lockfile..." >&2
set +e
VERIFY_RESULT=$("$SCRIPT_DIR/verify_lockfile.sh" --json 2>/dev/null)
VERIFY_RC=$?
set -e
VERIFY_VERDICT=$(parse_json_verdict "$VERIFY_RESULT")

if [ "$VERIFY_RC" -eq 2 ] || [ "$VERIFY_VERDICT" = "ERROR" ] || [ "$VERIFY_VERDICT" = "UNKNOWN" ]; then
  emit_resync_error "lockfile verification failed (expected JSON verdict from verify_lockfile.sh)" "RESYNC_VERIFY_PROBE_FAILED"
fi

echo "[5/5] Generating evidence report..." >&2

if $JSON_OUTPUT; then
  cat <<ENDJSON
{
  "verdict": "$VERIFY_VERDICT",
  "timestamp": "$TIMESTAMP",
  "source_root": "$SOURCE_ROOT",
  "drift_before": $DRIFT_REPORT,
  "actions_taken": ${#ACTIONS[@]},
  "verification_after": $VERIFY_RESULT
}
ENDJSON
else
  echo ""
  echo "=== Re-sync Summary ==="
  echo "Drift before: $DRIFT_VERDICT"
  echo "Actions taken: ${#ACTIONS[@]}"
  echo "Verification: $VERIFY_VERDICT"
fi

if [ "$VERIFY_VERDICT" = "PASS" ]; then
  echo "Re-sync complete. Snapshot verified." >&2
  exit 0
else
  echo "WARNING: Verification failed after re-sync." >&2
  exit 1
fi

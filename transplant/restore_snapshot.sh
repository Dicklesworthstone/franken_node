#!/usr/bin/env bash
# transplant/restore_snapshot.sh — Rehydrate the pi_agent_rust transplant snapshot.
#
# Reads transplant/transplant_manifest.txt, copies each listed relative path
# from <source-root>/<path> to <snapshot-dir>/<path>, preserving permissions
# but normalizing mtime to a deterministic value so subsequent hashing /
# diffing is reproducible.
#
# Defaults match the snapshot's documented provenance:
#   source-root  /data/projects/pi_agent_rust
#   snapshot-dir transplant/pi_agent_rust  (relative to this script)
#   manifest     transplant/transplant_manifest.txt
#   mtime        1970-01-01T00:00:00Z      (epoch — deterministic)
#
# Usage:
#   ./transplant/restore_snapshot.sh \
#     [--source-root PATH] \
#     [--snapshot-dir PATH] \
#     [--manifest FILE] \
#     [--mtime ISO-8601-UTC|@epoch] \
#     [--force] \
#     [--dry-run]
#
# Exit codes:
#   0 = OK (all manifest files copied or already up-to-date)
#   1 = PARTIAL (some manifest entries had no source file; rest copied)
#   2 = ERROR (invalid usage, missing manifest, IO failure)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="/data/projects/pi_agent_rust"
SNAPSHOT_DIR="${SCRIPT_DIR}/pi_agent_rust"
MANIFEST="${SCRIPT_DIR}/transplant_manifest.txt"
DETERMINISTIC_MTIME="1970-01-01T00:00:00Z"
FORCE=false
DRY_RUN=false

usage() {
  cat <<'USAGE'
Usage: restore_snapshot.sh [options]
  --source-root PATH     Upstream source root (default: /data/projects/pi_agent_rust).
  --snapshot-dir PATH    Destination snapshot dir (default: transplant/pi_agent_rust).
  --manifest FILE        Manifest of relative paths (default: transplant/transplant_manifest.txt).
  --mtime VALUE          ISO-8601 UTC timestamp or "@<epoch>" for normalized mtime
                         (default: 1970-01-01T00:00:00Z).
  --force                Overwrite existing snapshot files.
  --dry-run              Print planned copies without touching the filesystem.
  --help, -h             Show this help.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --source-root)
      SOURCE_ROOT="$2"
      shift 2
      ;;
    --snapshot-dir)
      SNAPSHOT_DIR="$2"
      shift 2
      ;;
    --manifest)
      MANIFEST="$2"
      shift 2
      ;;
    --mtime)
      DETERMINISTIC_MTIME="$2"
      shift 2
      ;;
    --force)
      FORCE=true
      shift
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ ! -d "$SOURCE_ROOT" ]; then
  echo "ERROR: Source root not found: $SOURCE_ROOT" >&2
  exit 2
fi
if [ ! -f "$MANIFEST" ]; then
  echo "ERROR: Manifest not found: $MANIFEST" >&2
  exit 2
fi

# Build the sorted, deduped list of manifest entries.
mapfile -t FILES < <(
  grep -v '^[[:space:]]*#' "$MANIFEST" \
    | sed -e '/^[[:space:]]*$/d' -e 's/\r$//' -e 's|^\./||' -e 's|^/||' \
    | LC_ALL=C sort -u
)

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "ERROR: Manifest is empty: $MANIFEST" >&2
  exit 2
fi

# touch -d accepts ISO-8601 and "@<epoch>" forms natively on GNU coreutils.
TOUCH_ARG="$DETERMINISTIC_MTIME"

if ! $DRY_RUN; then
  mkdir -p "$SNAPSHOT_DIR"
fi

COPIED=0
SKIPPED=0
MISSING=0
declare -a MISSING_PATHS=()

for relpath in "${FILES[@]}"; do
  [ -z "$relpath" ] && continue

  # Reject path traversal attempts in the manifest before touching the FS.
  case "$relpath" in
    /*|*..*)
      echo "ERROR: Rejecting unsafe manifest path: $relpath" >&2
      exit 2
      ;;
  esac

  src="${SOURCE_ROOT}/${relpath}"
  dst="${SNAPSHOT_DIR}/${relpath}"

  if [ ! -f "$src" ]; then
    MISSING=$((MISSING + 1))
    MISSING_PATHS+=("$relpath")
    echo "MISSING_SOURCE: $relpath" >&2
    continue
  fi

  if [ -e "$dst" ] && ! $FORCE; then
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  if $DRY_RUN; then
    echo "DRY: cp -p $src $dst"
    continue
  fi

  mkdir -p "$(dirname "$dst")"
  # cp -p preserves mode/owner/timestamps from source; we then normalize mtime.
  cp -p "$src" "$dst"
  touch -d "$TOUCH_ARG" "$dst"
  COPIED=$((COPIED + 1))
done

echo ""
echo "=== Transplant Snapshot Restore ==="
echo "Source root:     $SOURCE_ROOT"
echo "Snapshot dir:    $SNAPSHOT_DIR"
echo "Manifest:        $MANIFEST"
echo "Manifest count:  ${#FILES[@]}"
echo "Copied:          $COPIED"
echo "Skipped (exist): $SKIPPED"
echo "Missing source:  $MISSING"
echo "Normalized mtime: $DETERMINISTIC_MTIME"

if [ "$MISSING" -gt 0 ]; then
  echo "" >&2
  echo "WARNING: $MISSING manifest entries had no source file." >&2
  echo "         These are known-divergences vs the source repo:" >&2
  for p in "${MISSING_PATHS[@]}"; do
    echo "         - $p" >&2
  done
  exit 1
fi

exit 0

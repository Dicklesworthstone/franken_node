#!/usr/bin/env bash
# transplant/generate_lockfile.sh — Generate deterministic transplant lockfile.
#
# Usage:
#   ./transplant/generate_lockfile.sh \
#     [--source-root PATH] \
#     [--snapshot-dir PATH] \
#     [--manifest FILE] \
#     [--output FILE] \
#     [--generated-utc ISO-8601-UTC|now]
#
# Determinism note:
# - By default `generated_utc` is a fixed timestamp (`1970-01-01T00:00:00Z`)
#   so equivalent inputs produce byte-identical lockfiles.
# - Override with `--generated-utc` (or env `TRANSPLANT_LOCKFILE_GENERATED_UTC`)
#   when wall-clock metadata is required.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNAPSHOT_DIR="${SCRIPT_DIR}/pi_agent_rust"
OUTPUT="${SCRIPT_DIR}/TRANSPLANT_LOCKFILE.sha256"
SOURCE_ROOT="/data/projects/pi_agent_rust"
MANIFEST=""
MANIFEST_LABEL="transplant_manifest.txt"
GENERATED_UTC="${TRANSPLANT_LOCKFILE_GENERATED_UTC:-1970-01-01T00:00:00Z}"

usage() {
  cat <<'USAGE'
Usage: generate_lockfile.sh [options]
  --source-root PATH      Upstream source root metadata path.
  --snapshot-dir PATH     Snapshot directory to hash.
  --manifest FILE         Optional file list input (comments/blank lines ignored).
  --output FILE           Output lockfile path.
  --generated-utc VALUE   ISO-8601 UTC timestamp or "now".
  --help, -h              Show this help.
USAGE
}

discover_snapshot_files() {
  if command -v fd >/dev/null 2>&1; then
    fd --type file .
  else
    find . -type f -print
  fi
}

is_iso_utc() {
  [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]
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
      MANIFEST_LABEL="$2"
      shift 2
      ;;
    --output)
      OUTPUT="$2"
      shift 2
      ;;
    --generated-utc)
      GENERATED_UTC="$2"
      shift 2
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

if [ "$GENERATED_UTC" = "now" ]; then
  GENERATED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fi

if ! is_iso_utc "$GENERATED_UTC"; then
  echo "ERROR: --generated-utc must be ISO-8601 UTC (YYYY-MM-DDTHH:MM:SSZ) or 'now'" >&2
  exit 2
fi

if [ ! -d "$SNAPSHOT_DIR" ]; then
  echo "ERROR: Snapshot directory not found: $SNAPSHOT_DIR" >&2
  exit 2
fi

declare -a FILES=()
if [ -n "$MANIFEST" ]; then
  if [ ! -f "$MANIFEST" ]; then
    echo "ERROR: Manifest not found: $MANIFEST" >&2
    exit 2
  fi
  mapfile -t FILES < <(
    grep -v '^[[:space:]]*#' "$MANIFEST" \
      | sed -e '/^[[:space:]]*$/d' -e 's/\r$//' -e 's|^\./||' -e 's|^/||' \
      | LC_ALL=C sort -u
  )
else
  mapfile -t FILES < <(
    cd "$SNAPSHOT_DIR"
    discover_snapshot_files \
      | sed -e 's|^\./||' -e 's|^/||' -e 's/\r$//' \
      | LC_ALL=C sort -u
  )
fi

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "ERROR: No files discovered for lockfile generation." >&2
  exit 2
fi

tmp_entries="$(mktemp)"
trap 'rm -f "$tmp_entries"' EXIT

MISSING_COUNT=0
for relpath in "${FILES[@]}"; do
  [ -z "$relpath" ] && continue
  filepath="${SNAPSHOT_DIR}/${relpath}"
  if [ ! -f "$filepath" ]; then
    MISSING_COUNT=$((MISSING_COUNT + 1))
    echo "WARNING: File listed but not found: $relpath" >&2
    continue
  fi
  hash="$(sha256sum "$filepath" | awk '{print $1}')"
  printf '%s  %s\n' "$hash" "$relpath" >> "$tmp_entries"
done

ENTRY_COUNT="$(wc -l < "$tmp_entries" | tr -d ' ')"
if [ "$ENTRY_COUNT" -eq 0 ]; then
  echo "ERROR: No hashable files found under $SNAPSHOT_DIR" >&2
  exit 2
fi

if [ "$MISSING_COUNT" -gt 0 ]; then
  echo "ERROR: Manifest references $MISSING_COUNT missing file(s); refusing partial lockfile generation." >&2
  exit 2
fi

{
  printf '# TRANSPLANT LOCKFILE (sha256)\n'
  printf '# source_root: %s\n' "$SOURCE_ROOT"
  printf '# manifest: %s\n' "$MANIFEST_LABEL"
  printf '# entries: %s\n' "$ENTRY_COUNT"
  printf '# generated_utc: %s\n' "$GENERATED_UTC"
  printf '\n'
  cat "$tmp_entries"
} > "$OUTPUT"

echo "Generated lockfile: $OUTPUT ($ENTRY_COUNT entries)"

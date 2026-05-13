#!/bin/bash
# Batch-load all official extensions through the TS oracle harness.
# Outputs a summary of pass/fail for each extension.
#
# Usage: bash batch_load.sh [artifacts-dir]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARTIFACTS="${1:-$SCRIPT_DIR/../artifacts}"
HARNESS="$SCRIPT_DIR/load_extension.ts"
PI_MONO_ROOT="$SCRIPT_DIR/../../../legacy_pi_mono_code/pi-mono"
BUN="/home/ubuntu/.bun/bin/bun"

export NODE_PATH="$PI_MONO_ROOT/node_modules"

passed=0
failed=0
errors=()

# Find all single-file extensions (*.ts in artifacts root dirs)
for ext_dir in "$ARTIFACTS"/*/; do
    dir_name=$(basename "$ext_dir")

    # Skip non-extension directories
    [[ "$dir_name" == "community" ]] && continue
    [[ "$dir_name" == "npm-registry" ]] && continue
    [[ "$dir_name" == "third-party" ]] && continue
    [[ "$dir_name" == "agents-"* ]] && continue

    # Find the entry point
    entry=""
    if [[ -f "$ext_dir/index.ts" ]]; then
        entry="$ext_dir/index.ts"
    elif [[ -f "$ext_dir/$dir_name.ts" ]]; then
        entry="$ext_dir/$dir_name.ts"
    else
        # Look for any single .ts file
        ts_files=("$ext_dir"/*.ts)
        if [[ ${#ts_files[@]} -eq 1 && -f "${ts_files[0]}" ]]; then
            entry="${ts_files[0]}"
        fi
    fi

    if [[ -z "$entry" ]]; then
        echo "SKIP  $dir_name (no entry point found)"
        continue
    fi

    # Run the harness with a timeout
    result=$(timeout 15 "$BUN" run "$HARNESS" "$entry" /tmp 2>/dev/null || echo '{"success": false, "error": "timeout or crash"}')

    success=$(echo "$result" | grep -o '"success": *[a-z]*' | head -1 | grep -o 'true\|false')

    if [[ "$success" == "true" ]]; then
        echo "PASS  $dir_name"
        ((passed++))
    else
        error=$(echo "$result" | grep -o '"error": "[^"]*"' | head -1 | sed 's/"error": "//;s/"$//')
        echo "FAIL  $dir_name: ${error:0:80}"
        ((failed++))
        errors+=("$dir_name")
    fi
done

echo ""
echo "=== Summary ==="
echo "Passed: $passed"
echo "Failed: $failed"
if [[ ${#errors[@]} -gt 0 ]]; then
    echo "Failed extensions: ${errors[*]}"
fi

#!/bin/bash
FAILED=0
for script in scripts/check_*.py; do
    if ! python3 "$script" > "fail_${script##*/}.log" 2>&1; then
        echo "FAILED: $script"
        FAILED=$((FAILED+1))
    fi
done
echo "Total failed: $FAILED"

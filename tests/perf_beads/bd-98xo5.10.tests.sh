#!/usr/bin/env bash
# tests/perf_beads/bd-98xo5.10.tests.sh
#
# T10.tests script for bd-98xo5.10 (DGIS large-graph contagion
# simulator step benchmark). Builds and runs the Criterion harness added
# by this bead, then emits the parsed wall-clock means into the shared
# perf-bead JSONL schema.

set -uo pipefail

BEAD_ID="bd-98xo5.10.tests"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/run_perf_bead_test.sh
source "${SCRIPT_DIR}/scripts/run_perf_bead_test.sh"

perf_test_init "${BEAD_ID}"

perf_test_start "build"
perf_test_case "release-perf build (dgis_large_graph_bench)"
if perf_test_run_cargo build --profile release-perf -p frankenengine-node \
        --features advanced-features --bench dgis_large_graph_bench; then
    perf_test_pass
else
    perf_test_fail "release-perf build of dgis_large_graph_bench failed"
    perf_test_summary
    exit 1
fi
perf_test_summary || exit 1

perf_test_start "baseline"

BENCH_BIN=$(find "${SCRIPT_DIR}/target/release-perf/deps" \
            -maxdepth 1 -type f -name 'dgis_large_graph_bench-*' \
            -not -name '*.d' 2>/dev/null \
        | xargs -r ls -t 2>/dev/null \
        | head -n 1 || true)

extract_mean_ns() {
    local bench_filter=$1
    "${BENCH_BIN}" --bench "${bench_filter}" 2>&1 \
        | grep -oE 'time:[[:space:]]+\[[0-9.]+[[:space:]]+(ns|µs|ms|s)[[:space:]]+[0-9.]+[[:space:]]+(ns|µs|ms|s)[[:space:]]+[0-9.]+[[:space:]]+(ns|µs|ms|s)\]' \
        | head -n 1 \
        | python3 -c '
import re, sys
line = sys.stdin.read()
m = re.search(r"\[([0-9.]+)\s+(ns|µs|ms|s)\s+([0-9.]+)\s+(ns|µs|ms|s)\s+([0-9.]+)\s+(ns|µs|ms|s)\]", line)
if not m:
    print("0"); sys.exit(0)
mean, unit = float(m.group(3)), m.group(4)
ns = mean * {"ns": 1.0, "µs": 1_000.0, "ms": 1_000_000.0, "s": 1_000_000_000.0}[unit]
print(int(ns))
'
}

measure_case() {
    local case_name=$1 bench_filter=$2
    perf_test_case "${case_name}"
    if [ -z "${BENCH_BIN:-}" ] || [ ! -x "${BENCH_BIN}" ]; then
        perf_test_fail "criterion bench binary not present"
        return
    fi
    local mean_ns
    mean_ns=$(extract_mean_ns "${bench_filter}")
    if [ -z "${mean_ns:-}" ] || [ "${mean_ns}" = "0" ]; then
        perf_test_fail "could not parse criterion output for ${bench_filter}"
        return
    fi
    perf_test_measurement "${case_name}_mean_ns" "${mean_ns}" "nanoseconds"
    perf_test_pass
}

measure_case "requested_1000n_step_loop" \
    "dgis_large_graph/step_loop/requested_1000n"
measure_case "requested_10000n_step_loop" \
    "dgis_large_graph/step_loop/requested_10000n"
measure_case "requested_50000n_step_loop" \
    "dgis_large_graph/step_loop/requested_50000n"
measure_case "max_supported_1024n_dense_step_loop" \
    "dgis_large_graph/step_loop/requested_1024n"
perf_test_measurement "dgis_large_graph_bench_max_nodes" 50000 "nodes"
perf_test_summary || exit 1

echo
echo "test log: ${PERF_TEST_LOG}"
echo "Render with: python3 scripts/render_perf_test_summary.py ${PERF_TEST_LOG}"
exit 0

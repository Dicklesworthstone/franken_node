#!/usr/bin/env bash
# tests/perf_beads/bd-98xo5.6.tests.sh
#
# T6.tests script for bd-98xo5.6 (replay_bundle Vec::len → streaming
# ByteCounter). Owns the e2e test surface for T6 — see bd-98xo5.6.3
# for the full test-suite design.
#
# Phases:
#   build      — cargo build --profile release-perf --bench replay_bundle_gzip_bench
#   unit       — inline tests under tools::replay_bundle
#   property   — prop_byte_counter_matches_to_vec_len under --lib
#   integration — replay_bundle_byte_counter_no_vec_alloc integration test
#   baseline   — Criterion re-measure of streaming_counter/large_1000,
#                gate p95 ≤ 350 µs (was 335 µs; +5 % envelope).
#
# JSONL log at tests/artifacts/perf/test_runs/bd-98xo5.6.tests_<ts>/test_log.jsonl
# Consumed by scripts/render_perf_test_summary.py (bd-98xo5.15.2).

set -uo pipefail

BEAD_ID="bd-98xo5.6.tests"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/run_perf_bead_test.sh
source "${SCRIPT_DIR}/scripts/run_perf_bead_test.sh"

perf_test_init "${BEAD_ID}"

# ---------------------------------------------------------------------
# Phase 1: build.
# ---------------------------------------------------------------------
perf_test_start "build"
perf_test_case "release-perf build (replay_bundle_gzip_bench)"
if perf_test_run_cargo build --profile release-perf \
        -p frankenengine-node --bench replay_bundle_gzip_bench; then
    perf_test_pass
else
    perf_test_fail "release-perf build of replay_bundle_gzip_bench failed"
    perf_test_summary
    exit 1
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 2: inline unit tests.
# ---------------------------------------------------------------------
perf_test_start "unit"
perf_test_case "tools::replay_bundle::tests::byte_counter_*"
if perf_test_run_cargo test -p frankenengine-node --lib tools::replay_bundle; then
    perf_test_pass
else
    perf_test_fail "tools::replay_bundle inline tests failed"
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 3: property test.
# ---------------------------------------------------------------------
perf_test_start "property"
perf_test_case "prop_byte_counter_matches_to_vec_len"
if perf_test_run_cargo test -p frankenengine-node --lib \
        tools::replay_bundle::tests::prop_byte_counter_matches_to_vec_len \
        -- --nocapture; then
    perf_test_pass
else
    perf_test_fail "prop_byte_counter_matches_to_vec_len regression"
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 4: integration regression test for streaming-write contract.
# ---------------------------------------------------------------------
perf_test_start "integration"
perf_test_case "replay_bundle_byte_counter_no_vec_alloc"
if perf_test_run_cargo test -p frankenengine-node \
        --test replay_bundle_byte_counter_no_vec_alloc; then
    perf_test_pass
else
    perf_test_fail "replay_bundle_byte_counter_no_vec_alloc regression"
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 5: baseline re-measure.
# ---------------------------------------------------------------------
perf_test_start "baseline"

BENCH_BIN=$(find "${SCRIPT_DIR}/target/release-perf/deps" \
            -maxdepth 1 -type f -name 'replay_bundle_gzip_bench-*' \
            -not -name '*.d' 2>/dev/null \
        | xargs -r ls -t 2>/dev/null \
        | head -n 1 || true)

extract_mean_ns() {
    local bench_id=$1
    "${BENCH_BIN}" --bench "${bench_id}" 2>&1 \
        | grep -oE 'time:[[:space:]]+\[[0-9.]+[[:space:]]+(ns|µs|ms)[[:space:]]+[0-9.]+[[:space:]]+(ns|µs|ms)[[:space:]]+[0-9.]+[[:space:]]+(ns|µs|ms)\]' \
        | head -n 1 \
        | python3 -c '
import re, sys
line = sys.stdin.read()
m = re.search(r"\[([0-9.]+)\s+(ns|µs|ms)\s+([0-9.]+)\s+(ns|µs|ms)\s+([0-9.]+)\s+(ns|µs|ms)\]", line)
if not m:
    print("0"); sys.exit(0)
mean, unit = float(m.group(3)), m.group(4)
ns = mean * {"ns": 1.0, "µs": 1_000.0, "ms": 1_000_000.0}[unit]
print(int(ns))
'
}

assert_under_budget() {
    local case_name=$1 bench_id=$2 budget_ns=$3
    perf_test_case "${case_name}"
    if [ -z "${BENCH_BIN:-}" ] || [ ! -x "${BENCH_BIN}" ]; then
        perf_test_skip "criterion bench binary not present"
        return
    fi
    local mean_ns
    mean_ns=$(extract_mean_ns "${bench_id}")
    if [ -z "${mean_ns:-}" ] || [ "${mean_ns}" = "0" ]; then
        perf_test_fail "could not parse criterion output for ${bench_id}"
        return
    fi
    perf_test_measurement "${case_name}_ns" "${mean_ns}" "nanoseconds"
    if awk -v m="${mean_ns}" -v b="${budget_ns}" 'BEGIN { exit !(m+0 <= b+0) }'; then
        perf_test_pass
    else
        perf_test_fail "${case_name} exceeded ${budget_ns} ns budget (got ${mean_ns} ns)"
    fi
}

# T6.3 perf target: streaming_counter/large_1000 ≤ 350 µs (was 335 µs).
assert_under_budget "streaming_counter_large_1000" \
    "replay_bundle_event_size/streaming_counter/large_1000" 350000
perf_test_summary || exit 1

echo
echo "test log: ${PERF_TEST_LOG}"
echo "Render with: python3 scripts/render_perf_test_summary.py ${PERF_TEST_LOG}"
exit 0

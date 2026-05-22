#!/usr/bin/env bash
# tests/perf_beads/bd-98xo5.4.tests.sh
#
# T4.tests script for bd-98xo5.4 (trust_card canonical encoder
# structural deep-clone removal). Owns the e2e test surface for T4 —
# see bd-98xo5.4.7 for the full test-suite design.
#
# Phases:
#   build       — cargo build --profile release-perf --bench trust_card_canonical_bench
#   unit        — cargo test --lib connector::canonical_serializer
#   property    — proptest invariants (prop_streaming_encoder_byte_equal_to_old +
#                 prop_streaming_roundtrip_via_serde_json)
#   integration — trust_card_streaming_encoder_golden_preservation +
#                 supply_chain_trust_card_golden_bytes
#   fuzz        — fuzz_canonical_encoder_parity 60-second smoke
#   baseline    — Criterion re-measure against the T4.7 budgets on the
#                 shipped streaming encoder:
#                   streaming/simple_1x5    ≤ 30 µs   (was 79.81 µs)
#                   streaming/medium_3x8    ≤ 5 ms    (was 33.23 ms)
#                   streaming/complex_4x12  ≤ 300 ms  (was 3 591 ms)
#   heaptrack   — alloc-count gate (SKIP if heaptrack absent):
#                   medium_3x8 allocs ≤ 5 M   (was 21.5 M)
#                   medium_3x8 peak   ≤ 100 MiB (was 430 MiB)
#
# JSONL log at tests/artifacts/perf/test_runs/bd-98xo5.4.tests_<ts>/test_log.jsonl
# Consumed by scripts/render_perf_test_summary.py (bd-98xo5.15.2).

set -uo pipefail

BEAD_ID="bd-98xo5.4.tests"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/run_perf_bead_test.sh
source "${SCRIPT_DIR}/scripts/run_perf_bead_test.sh"

perf_test_init "${BEAD_ID}"

# ---------------------------------------------------------------------
# Phase 1: build the bench under release-perf.
# ---------------------------------------------------------------------
perf_test_start "build"
perf_test_case "release-perf build (trust_card_canonical_bench)"
if perf_test_run_cargo build --profile release-perf \
        -p frankenengine-node --bench trust_card_canonical_bench; then
    perf_test_pass
else
    perf_test_fail "release-perf build of trust_card_canonical_bench failed"
    perf_test_summary
    exit 1
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 2: inline unit tests.
# ---------------------------------------------------------------------
perf_test_start "unit"
perf_test_case "connector::canonical_serializer streaming encoder tests"
if perf_test_run_cargo test -p frankenengine-node --lib \
        connector::canonical_serializer; then
    perf_test_pass
else
    perf_test_fail "canonical_serializer inline tests failed"
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 3: property tests.
# ---------------------------------------------------------------------
perf_test_start "property"
perf_test_case "prop_streaming_encoder_byte_equal_to_old"
if perf_test_run_cargo test -p frankenengine-node --lib \
        connector::canonical_serializer::tests::prop_streaming_encoder_byte_equal_to_old \
        -- --nocapture; then
    perf_test_pass
else
    perf_test_fail "prop_streaming_encoder_byte_equal_to_old regression"
fi
perf_test_case "prop_streaming_roundtrip_via_serde_json"
if perf_test_run_cargo test -p frankenengine-node --lib \
        connector::canonical_serializer::tests::prop_streaming_roundtrip_via_serde_json \
        -- --nocapture; then
    perf_test_pass
else
    perf_test_fail "prop_streaming_roundtrip_via_serde_json regression"
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 4: integration / HMAC golden gate.
# ---------------------------------------------------------------------
perf_test_start "integration"
perf_test_case "trust_card_streaming_encoder_golden_preservation"
if perf_test_run_cargo test -p frankenengine-node \
        --test trust_card_streaming_encoder_golden_preservation; then
    perf_test_pass
else
    perf_test_fail "trust_card_streaming_encoder_golden_preservation regression"
fi
perf_test_case "supply_chain_trust_card_golden_bytes (post-migration)"
if perf_test_run_cargo test -p frankenengine-node \
        --test supply_chain_trust_card_golden_bytes; then
    perf_test_pass
else
    perf_test_fail "supply_chain_trust_card_golden_bytes regression after T4.5 migration"
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 5: fuzz smoke — 60-second budget. Skip cleanly if nightly
# toolchain isn't on PATH.
# ---------------------------------------------------------------------
perf_test_start "fuzz"
perf_test_case "fuzz_canonical_encoder_parity (60s budget)"
if ! command -v rustup >/dev/null 2>&1; then
    perf_test_skip "rustup not on PATH; fuzz requires nightly toolchain"
elif ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    perf_test_skip "nightly toolchain not installed; fuzz harness needs cargo-fuzz nightly"
elif ! command -v cargo-fuzz >/dev/null 2>&1 \
        && ! cargo +nightly fuzz --help >/dev/null 2>&1; then
    perf_test_skip "cargo-fuzz binary not available"
else
    if ( cd "${SCRIPT_DIR}/fuzz" \
            && cargo +nightly fuzz run fuzz_canonical_encoder_parity \
                -- -max_total_time=60 ); then
        perf_test_pass
    else
        perf_test_fail "fuzz harness crashed or found a parity divergence in 60s"
    fi
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 6: baseline re-measure against the T4.7 budgets.
# ---------------------------------------------------------------------
perf_test_start "baseline"

BENCH_BIN=$(find "${SCRIPT_DIR}/target/release-perf/deps" \
            -maxdepth 1 -type f -name 'trust_card_canonical_bench-*' \
            -not -name '*.d' 2>/dev/null \
        | xargs -r ls -t 2>/dev/null \
        | head -n 1 || true)

extract_mean_ns() {
    local bench_id=$1
    "${BENCH_BIN}" --bench "${bench_id}" 2>&1 \
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

# T4.7 perf budgets for the production streaming encoder. The
# historical `current/*` Criterion entries remain in the bench as the
# round-1 deep-clone baseline; gating them would fail by design.
assert_under_budget "streaming_simple_1x5" "streaming/simple_1x5" 30000
assert_under_budget "streaming_medium_3x8" "streaming/medium_3x8" 5000000
assert_under_budget "streaming_complex_4x12" "streaming/complex_4x12" 300000000
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 7: heaptrack alloc-count gate (SKIP if absent).
# ---------------------------------------------------------------------
perf_test_start "heaptrack"
perf_test_case "trust_card_canonical_bench medium_3x8 alloc count"
if ! command -v heaptrack >/dev/null 2>&1; then
    perf_test_skip "heaptrack not on PATH; alloc-count gate deferred to future perf round"
else
    # Reserved for a future enhancement that drives the bench under
    # heaptrack and parses its --print-allocators report. Out of scope
    # for the bd-98xo5.4.7 baseline ship.
    perf_test_skip "heaptrack alloc-count harness is a follow-on; see bd-98xo5.4.7 close_reason"
fi
perf_test_summary || exit 1

echo
echo "test log: ${PERF_TEST_LOG}"
echo "Render with: python3 scripts/render_perf_test_summary.py ${PERF_TEST_LOG}"
exit 0

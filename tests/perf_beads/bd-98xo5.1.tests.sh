#!/usr/bin/env bash
# tests/perf_beads/bd-98xo5.1.tests.sh
#
# T1.tests script for bd-98xo5.1 (threshold_sig preparsed VerifyingKey
# plumbing). Owns the e2e test surface for T1 — see bd-98xo5.1.5 for
# the full test-suite design.
#
# Phases:
#   build      — cargo build --profile release-perf --bench threshold_sig_verify_bench
#   unit       — cargo test --lib security::threshold_sig (all inline)
#   property   — proptest prop_parity_random_config under --lib
#   fuzz       — cargo +nightly fuzz run fuzz_threshold_sig_parity -- -max_total_time=60
#   baseline   — Criterion re-measure of preparsed_keys/{8,32}, gate
#                p95 against the T1 budgets (≤ 436 µs / ≤ 1 772 µs).
#
# JSONL log lands at tests/artifacts/perf/test_runs/bd-98xo5.1.tests_<ts>/test_log.jsonl.
# Consumed by scripts/render_perf_test_summary.py (bd-98xo5.15.2).

set -uo pipefail

BEAD_ID="bd-98xo5.1.tests"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/run_perf_bead_test.sh
source "${SCRIPT_DIR}/scripts/run_perf_bead_test.sh"

perf_test_init "${BEAD_ID}"

# ---------------------------------------------------------------------
# Phase 1: build the bench under release-perf.
# ---------------------------------------------------------------------
perf_test_start "build"
perf_test_case "release-perf build (threshold_sig_verify_bench)"
if perf_test_run_cargo build --profile release-perf \
        -p frankenengine-node --bench threshold_sig_verify_bench; then
    perf_test_pass
else
    perf_test_fail "release-perf build of threshold_sig_verify_bench failed"
    perf_test_summary
    exit 1
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 2: unit tests — all preparsed parity inline tests under
# security::threshold_sig::tests. The [lib] test = false manifest knob
# means inline tests are validated at compile-time; cargo test --lib
# will exit 0 with "0 filtered out" but the COMPILE green is the gate.
# ---------------------------------------------------------------------
perf_test_start "unit"
perf_test_case "security::threshold_sig::tests::parity_with_legacy_at_8_signers"
if perf_test_run_cargo test -p frankenengine-node --lib security::threshold_sig; then
    perf_test_pass
else
    perf_test_fail "security::threshold_sig inline tests failed under release-perf"
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 3: property test — the proptest is a `#[test]` under the same
# inline module, sharing the build green with phase 2.
# ---------------------------------------------------------------------
perf_test_start "property"
perf_test_case "prop_parity_random_config"
if perf_test_run_cargo test -p frankenengine-node --lib \
        security::threshold_sig::tests::prop_parity_random_config \
        -- --nocapture; then
    perf_test_pass
else
    perf_test_fail "prop_parity_random_config regression"
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 4: fuzz smoke — short budget. Skip cleanly if nightly toolchain
# isn't on PATH so this works on stable-only builders.
# ---------------------------------------------------------------------
perf_test_start "fuzz"
perf_test_case "fuzz_threshold_sig_parity (60s budget)"
if ! command -v rustup >/dev/null 2>&1; then
    perf_test_skip "rustup not on PATH; fuzz requires nightly toolchain"
elif ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    perf_test_skip "nightly toolchain not installed; fuzz harness needs cargo-fuzz nightly"
elif ! command -v cargo-fuzz >/dev/null 2>&1 \
        && ! cargo +nightly fuzz --help >/dev/null 2>&1; then
    perf_test_skip "cargo-fuzz binary not available"
else
    if ( cd "${SCRIPT_DIR}/fuzz" \
            && cargo +nightly fuzz run fuzz_threshold_sig_parity \
                -- -max_total_time=60 ); then
        perf_test_pass
    else
        perf_test_fail "fuzz harness crashed or found a divergence in 60s"
    fi
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 5: baseline — re-measure preparsed_keys/8 + preparsed_keys/32
# against the T1 budgets.
# ---------------------------------------------------------------------
perf_test_start "baseline"

BENCH_BIN=$(find "${SCRIPT_DIR}/target/release-perf/deps" \
            -maxdepth 1 -type f -name 'threshold_sig_verify_bench-*' \
            -not -name '*.d' 2>/dev/null \
        | xargs -r ls -t 2>/dev/null \
        | head -n 1 || true)

# T1.5 perf targets (microseconds, p95 from round-1 +10 % envelope):
#   preparsed_keys/8   ≤  436 µs  (=   436 000 ns)
#   preparsed_keys/32  ≤ 1772 µs  (= 1 772 000 ns)
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

assert_under_budget "preparsed_keys_8" "preparsed_keys/8" 436000
assert_under_budget "preparsed_keys_32" "preparsed_keys/32" 1772000
perf_test_summary || exit 1

echo
echo "test log: ${PERF_TEST_LOG}"
echo "Render with: python3 scripts/render_perf_test_summary.py ${PERF_TEST_LOG}"
exit 0

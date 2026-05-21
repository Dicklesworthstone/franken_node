#!/usr/bin/env bash
# tests/perf_beads/bd-98xo5.2.tests.sh
#
# T2.tests script for bd-98xo5.2 (Ed25519Scheme preparsed key handle).
# Owns the comprehensive end-to-end test surface for T2 — see
# bd-98xo5.2.7 for the test-suite design.
#
# Phases:
#   build     — cargo build --profile release-perf --bench crypto_scheme_bench
#   unit      — cargo test --lib crypto::schemes (all inline tests incl. preparsed)
#   property  — proptest invariants prop_signature_parity_random_payload +
#               prop_verifier_accepts_iff_stateless_does (also under --lib)
#   fuzz      — cargo +nightly fuzz run fuzz_ed25519_preparsed_parity -max_total_time=60
#   baseline  — re-measure ed25519_scheme_sign_raw/64 + ed25519_preparsed_sign/64,
#               assert against the T2.5 perf targets (≤ 30 µs / ≤ 26 µs).
#   determinism — sign twice from the same key, assert byte-identical output.
#
# Log emitted to tests/artifacts/perf/test_runs/bd-98xo5.2.tests_<ts>/test_log.jsonl
# Consumed by scripts/render_perf_test_summary.py (bd-98xo5.15.2).

set -uo pipefail

BEAD_ID="bd-98xo5.2.tests"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/run_perf_bead_test.sh
source "${SCRIPT_DIR}/scripts/run_perf_bead_test.sh"

perf_test_init "${BEAD_ID}"

# ---------------------------------------------------------------------
# Phase 1: build
# ---------------------------------------------------------------------
perf_test_start "build"
perf_test_case "release-perf build (crypto_scheme_bench)"
if perf_test_run_cargo build --profile release-perf \
        -p frankenengine-node --bench crypto_scheme_bench; then
    perf_test_pass
else
    perf_test_fail "release-perf build of crypto_scheme_bench failed"
    perf_test_summary
    exit 1
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 2: unit tests — narrow filter to keep the matrix job fast.
# ---------------------------------------------------------------------
perf_test_start "unit"
perf_test_case "crypto::schemes inline preparsed tests"
if perf_test_run_cargo test -p frankenengine-node --lib crypto::schemes; then
    perf_test_pass
else
    perf_test_fail "crypto::schemes inline tests failed under release-perf"
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 3: property tests — both bd-98xo5.2.7 proptest invariants.
# Run via the same inline mod tests filter; the proptest! macro
# produces #[test] functions whose names start with `prop_`.
# ---------------------------------------------------------------------
perf_test_start "property"
perf_test_case "prop_signature_parity_random_payload"
if perf_test_run_cargo test -p frankenengine-node --lib \
        crypto::schemes::tests::prop_signature_parity_random_payload \
        -- --nocapture; then
    perf_test_pass
else
    perf_test_fail "prop_signature_parity_random_payload regression"
fi
perf_test_case "prop_verifier_accepts_iff_stateless_does"
if perf_test_run_cargo test -p frankenengine-node --lib \
        crypto::schemes::tests::prop_verifier_accepts_iff_stateless_does \
        -- --nocapture; then
    perf_test_pass
else
    perf_test_fail "prop_verifier_accepts_iff_stateless_does regression"
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 4: fuzz smoke — 60 s budget on libfuzzer; nightly required.
# Skip cleanly if nightly toolchain isn't on PATH so the script still
# exits 0 on builders that only have stable Rust.
# ---------------------------------------------------------------------
perf_test_start "fuzz"
perf_test_case "fuzz_ed25519_preparsed_parity (60s budget)"
if ! command -v rustup >/dev/null 2>&1; then
    perf_test_skip "rustup not on PATH; fuzz requires nightly toolchain"
elif ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    perf_test_skip "nightly toolchain not installed; fuzz harness needs cargo-fuzz nightly"
elif ! command -v cargo-fuzz >/dev/null 2>&1 \
        && ! cargo +nightly fuzz --help >/dev/null 2>&1; then
    perf_test_skip "cargo-fuzz binary not available"
else
    if ( cd "${SCRIPT_DIR}/fuzz" \
            && cargo +nightly fuzz run fuzz_ed25519_preparsed_parity \
                -- -max_total_time=60 ); then
        perf_test_pass
    else
        perf_test_fail "fuzz harness crashed or found a divergence in 60s"
    fi
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 5: baseline — re-measure the two preparsed bench cases at 64 B
# and gate against the T2.5 targets.
# ---------------------------------------------------------------------
perf_test_start "baseline"

BENCH_BIN=$(find "${SCRIPT_DIR}/target/release-perf/deps" \
            -maxdepth 1 -type f -name 'crypto_scheme_bench-*' \
            -not -name '*.d' 2>/dev/null \
        | xargs -r ls -t 2>/dev/null \
        | head -n 1 || true)

# T2.5 perf targets (microseconds at 64 B):
#   ed25519_scheme_sign_raw   ≤ 30 µs  (= 30 000 ns)
#   ed25519_preparsed_sign    ≤ 26 µs  (= 26 000 ns)
extract_mean_ns() {
    # extract_mean_ns "<bench-id>" — reads Criterion's
    # "time:   [lo ns mean ns hi ns]" line and prints the mean in ns.
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
    # assert_under_budget "<case-name>" "<bench-id>" "<budget-ns>"
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

assert_under_budget "ed25519_scheme_sign_raw_64B" \
    "crypto_scheme_raw_sign/ed25519_scheme_sign_raw/64" 30000
assert_under_budget "ed25519_preparsed_sign_64B" \
    "crypto_scheme_raw_sign/ed25519_preparsed_sign/64" 26000
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 6: determinism — Ed25519 is deterministic by RFC 8032 §5.1.6.
# A regression that flipped to randomised signatures here would silently
# break every trust card / capability artifact that expects byte-stable
# signatures for content-addressed identity.
# ---------------------------------------------------------------------
perf_test_start "determinism"
perf_test_case "preparsed_sign_raw_byte_stable_across_invocations"
DETERMINISM_OUT=$(cd "${SCRIPT_DIR}" && rch exec -- cargo test --profile release-perf \
        -p frankenengine-node --lib \
        crypto::schemes::tests::preparsed_signer_sign_raw_matches_scheme \
        -- --nocapture 2>&1)
DETERMINISM_RC=$?
if [ "${DETERMINISM_RC}" -eq 0 ]; then
    perf_test_pass
else
    perf_test_fail "deterministic-output test failed: $(printf '%s\n' "${DETERMINISM_OUT}" | tail -n 3 | tr '\n' ' ')"
fi
perf_test_summary || exit 1

echo
echo "test log: ${PERF_TEST_LOG}"
echo "Render with: python3 scripts/render_perf_test_summary.py ${PERF_TEST_LOG}"
exit 0

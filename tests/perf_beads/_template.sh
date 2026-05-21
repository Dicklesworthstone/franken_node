#!/usr/bin/env bash
# tests/perf_beads/_template.sh
#
# Canonical reference template for a `bd-98xo5.X.tests` script under
# the T15 perf-bead testing harness (bd-98xo5.15, doc:
# docs/dev/perf_bead_testing.md). Copy this file when authoring a new
# Tx.tests opt-test bead:
#
#     cp tests/perf_beads/_template.sh \
#        tests/perf_beads/bd-98xo5.X.tests.sh
#     # then edit BEAD_ID, swap in the right cases.
#
# The template exercises the full producer→consumer contract on the
# crypto_scheme_bench surface (bd-98xo5.2). Acceptance per the bead:
#
#   - `bash tests/perf_beads/_template.sh` exits 0 on a clean repo.
#   - The produced log is parseable by
#     `scripts/render_perf_test_summary.py` and renders "✓ PASS".
#
# Phases included (use whichever apply, in this order — drop the
# ones that don't and add `property` / `fuzz` / `e2e` / `cleanup` as
# your bead requires):
#
#   build    — cargo build under release-perf.
#   unit     — narrow `cargo test` invocations under release-perf.
#   baseline — Criterion re-measure + budget comparison.
#
# Author: SilentCompass (bd-98xo5.15.3, parent: bd-98xo5.15).

set -uo pipefail

BEAD_ID="bd-98xo5.0.template"

# Locate the repo root by walking up from this script's location.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/run_perf_bead_test.sh
source "${SCRIPT_DIR}/scripts/run_perf_bead_test.sh"

perf_test_init "${BEAD_ID}"

# ---------------------------------------------------------------------
# Build phase — every Tx.tests script must build under release-perf so
# the binary it later measures is the canonical perf profile (see
# docs/dev/profiling.md and scripts/check_release_perf_profile.py).
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
# Unit phase — run the narrow inline tests that exercise the optimised
# call sites. Keep the test selector as tight as possible; this is not
# the place for the full crate test suite.
# ---------------------------------------------------------------------
perf_test_start "unit"
perf_test_case "crypto::schemes preparsed-handle smoke"
if perf_test_run_cargo test --profile release-perf \
        -p frankenengine-node --lib crypto::schemes::tests; then
    perf_test_pass
else
    perf_test_fail "crypto::schemes::tests failed under release-perf"
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Baseline phase — re-run Criterion on a single benchmark, parse the
# reported time, compare against the perf budget. If the metric blows
# its budget, the phase fails and `perf_test_summary` returns non-zero.
#
# This block is documented as the reference shape; replace
# `BENCH_NAME` / `METRIC_NAME` / `BUDGET_NS` for your bead's surface.
# ---------------------------------------------------------------------
perf_test_start "baseline"
perf_test_case "ed25519_dalek_direct_sign_64B"

# Find the bench binary. Criterion produces deps-prefixed binaries
# under target/release-perf/deps/; the suffix is a content hash. We
# pick the newest one matching the bench name.
BENCH_BIN=$(find "${SCRIPT_DIR}/target/release-perf/deps" \
            -maxdepth 1 -type f -name 'crypto_scheme_bench-*' \
            -not -name '*.d' 2>/dev/null \
        | xargs -r ls -t 2>/dev/null \
        | head -n 1 || true)

if [ -z "${BENCH_BIN:-}" ] || [ ! -x "${BENCH_BIN}" ]; then
    perf_test_skip "criterion bench binary not present (was the build skipped?)"
else
    BUDGET_NS=30000  # 30 µs — dalek_direct must remain under this.
    BENCH_OUT=$("${BENCH_BIN}" --bench "ed25519_dalek_direct/64" 2>&1 || true)
    # Criterion prints "time:   [<lower> ns <mean> ns <upper> ns]". We
    # extract the middle value (the mean) — that's what the perf
    # budget gates on.
    MEASURED_NS=$(printf '%s\n' "${BENCH_OUT}" \
        | grep -oE 'time:[[:space:]]+\[[0-9.]+[[:space:]]+(ns|µs|ms)[[:space:]]+[0-9.]+[[:space:]]+(ns|µs|ms)[[:space:]]+[0-9.]+[[:space:]]+(ns|µs|ms)\]' \
        | head -n 1 \
        | grep -oE '[0-9.]+' \
        | sed -n 2p || true)
    if [ -z "${MEASURED_NS:-}" ]; then
        perf_test_fail "could not parse criterion time output from ed25519_dalek_direct/64"
    else
        perf_test_measurement "ed25519_dalek_direct_sign_64B_ns" "${MEASURED_NS}" "nanoseconds"
        # Floating-point comparison via awk to avoid bc-dependence.
        if awk -v m="${MEASURED_NS}" -v b="${BUDGET_NS}" 'BEGIN { exit !(m+0 <= b+0) }'; then
            perf_test_pass
        else
            perf_test_fail "ed25519_dalek_direct/64 exceeded ${BUDGET_NS} ns budget (got ${MEASURED_NS} ns)"
        fi
    fi
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Done. Tx.tests scripts may render their own summary here for human
# consumption, but the JSONL log is the ground-truth that the CI gate
# (.github/workflows/perf-bead-tests.yml) and downstream tooling read.
# ---------------------------------------------------------------------
echo
echo "test log: ${PERF_TEST_LOG}"
echo "Render with: python3 scripts/render_perf_test_summary.py ${PERF_TEST_LOG}"
exit 0

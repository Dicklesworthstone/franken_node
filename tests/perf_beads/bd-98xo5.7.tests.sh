#!/usr/bin/env bash
# tests/perf_beads/bd-98xo5.7.tests.sh
#
# T7.tests script for bd-98xo5.7 (fleet_transport canonicalize
# path-alloc cleanup). Owns the e2e test surface for T7 — see
# bd-98xo5.7.3 for the full test-suite design.
#
# Phases:
#   build       — release-perf library build
#   unit        — cargo test --lib control_plane::fleet_transport
#   property    — proptest invariants
#   integration — fleet_transport_canonical_byte_stability
#   baseline    — SKIP (no Criterion bench for this surface — declined
#                 in T7 body since the change is allocation-only)
#
# JSONL log at tests/artifacts/perf/test_runs/bd-98xo5.7.tests_<ts>/test_log.jsonl
# Consumed by scripts/render_perf_test_summary.py (bd-98xo5.15.2).

set -uo pipefail

BEAD_ID="bd-98xo5.7.tests"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/run_perf_bead_test.sh
source "${SCRIPT_DIR}/scripts/run_perf_bead_test.sh"

perf_test_init "${BEAD_ID}"

# ---------------------------------------------------------------------
# Phase 1: build (library only — no bench surface for this bead).
# ---------------------------------------------------------------------
perf_test_start "build"
perf_test_case "release-perf library build"
if perf_test_run_cargo build --profile release-perf -p frankenengine-node --lib; then
    perf_test_pass
else
    perf_test_fail "release-perf library build failed"
    perf_test_summary
    exit 1
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 2: inline unit tests.
# ---------------------------------------------------------------------
perf_test_start "unit"
perf_test_case "control_plane::fleet_transport canonicalize_* tests"
if perf_test_run_cargo test -p frankenengine-node --lib \
        control_plane::fleet_transport; then
    perf_test_pass
else
    perf_test_fail "fleet_transport inline tests failed"
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 3: property tests.
# ---------------------------------------------------------------------
perf_test_start "property"
perf_test_case "prop_canonical_bytes_idempotent"
if perf_test_run_cargo test -p frankenengine-node --lib \
        control_plane::fleet_transport::tests::prop_canonical_bytes_idempotent \
        -- --nocapture; then
    perf_test_pass
else
    perf_test_fail "prop_canonical_bytes_idempotent regression"
fi
perf_test_case "prop_float_error_format_pins_legacy_template"
if perf_test_run_cargo test -p frankenengine-node --lib \
        control_plane::fleet_transport::tests::prop_float_error_format_pins_legacy_template \
        -- --nocapture; then
    perf_test_pass
else
    perf_test_fail "prop_float_error_format_pins_legacy_template regression"
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 4: integration regression test.
# ---------------------------------------------------------------------
perf_test_start "integration"
perf_test_case "fleet_transport_canonical_byte_stability"
if perf_test_run_cargo test -p frankenengine-node \
        --test fleet_transport_canonical_byte_stability; then
    perf_test_pass
else
    perf_test_fail "fleet_transport_canonical_byte_stability regression"
fi
perf_test_summary || exit 1

# ---------------------------------------------------------------------
# Phase 5: baseline (SKIP — declined in T7 body).
# ---------------------------------------------------------------------
perf_test_start "baseline"
perf_test_case "no-criterion-bench-for-this-surface"
perf_test_skip "T7 body declined a dedicated Criterion bench; the canonicalize path-alloc cleanup is allocation-only and validated by the unit + property + integration tiers above. A heaptrack-driven alloc-count gate is documented as follow-on work in bd-98xo5.7.3 close_reason."
perf_test_summary || exit 1

echo
echo "test log: ${PERF_TEST_LOG}"
echo "Render with: python3 scripts/render_perf_test_summary.py ${PERF_TEST_LOG}"
exit 0

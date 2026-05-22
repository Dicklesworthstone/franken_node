#!/usr/bin/env bash
# tests/perf_beads/bd-98xo5.5.tests.sh
#
# T5.tests script for bd-98xo5.5 (DGIS NodeId u32 interning).

set -uo pipefail

BEAD_ID="bd-98xo5.5.tests"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/run_perf_bead_test.sh
source "${SCRIPT_DIR}/scripts/run_perf_bead_test.sh"

perf_test_init "${BEAD_ID}"

perf_test_start "build"
perf_test_case "dgis_contagion_simulator release-perf build"
if perf_test_run_cargo test --profile release-perf -p frankenengine-node \
        --features advanced-features --test dgis_contagion_simulator --no-run; then
    perf_test_pass
else
    perf_test_fail "release-perf build of dgis_contagion_simulator failed"
    perf_test_summary
    exit 1
fi
perf_test_summary || exit 1

perf_test_start "unit"
perf_test_case "dgis::node_interner inline tests"
if perf_test_run_cargo test -p frankenengine-node --lib dgis::node_interner; then
    perf_test_pass
else
    perf_test_fail "dgis::node_interner inline tests failed"
fi
perf_test_case "dgis::contagion_graph inline tests"
if perf_test_run_cargo test -p frankenengine-node --lib dgis::contagion_graph; then
    perf_test_pass
else
    perf_test_fail "dgis::contagion_graph inline tests failed"
fi
perf_test_summary || exit 1

perf_test_start "property"
perf_test_case "prop_simulation_trace_deterministic_under_interning"
if perf_test_run_cargo test -p frankenengine-node --lib \
        dgis::contagion_simulator::tests::prop_simulation_trace_deterministic_under_interning \
        -- --nocapture; then
    perf_test_pass
else
    perf_test_fail "DGIS campaign trace determinism property failed"
fi
perf_test_summary || exit 1

perf_test_start "integration"
for test_name in \
    dgis_contagion_simulator \
    dgis_atc_interop \
    dgis_migration_gate \
    dgis_trust_card_integration
do
    perf_test_case "${test_name}"
    if perf_test_run_cargo test -p frankenengine-node --features advanced-features \
            --test "${test_name}"; then
        perf_test_pass
    else
        perf_test_fail "${test_name} failed"
    fi
done
perf_test_summary || exit 1

perf_test_start "profile"
perf_test_case "bd-98xo5.5.4 owns perf rebaseline artifacts"
perf_test_skip "perf record artifact capture is owned by bd-98xo5.5.4; this T5 harness gates build/unit/property/integration coverage"
perf_test_summary || exit 1

echo
echo "test log: ${PERF_TEST_LOG}"
echo "Render with: python3 scripts/render_perf_test_summary.py ${PERF_TEST_LOG}"
exit 0

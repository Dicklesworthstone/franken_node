#!/usr/bin/env bash
# Isolated-core timing-test lane (bd-m87xv).
#
# Wall-clock timing-variance assertions are only meaningful on a quiesced,
# core-pinned host; on a shared multi-agent build machine a single scheduler
# preemption blows any nanosecond ratio bound. This script:
#
#   1. Builds the inline-lib-test binary (the timing tests live in inline
#      #[cfg(test)] modules, which only compile under
#      `--cfg franken_node_inline_tests`).
#   2. Pins the test binary to a single core (the highest-numbered online CPU
#      by default; override with TIMING_TEST_CORE=<n>).
#   3. Sets FRANKEN_NODE_TIMING_TESTS=1 so the tests' timing thresholds
#      actually assert (without it the measured paths run but thresholds are
#      skipped — see crate::testing::timing_assertions_enabled).
#   4. Runs the timing-sensitive tests single-threaded, including the
#      #[ignore]-tagged ones.
#
# Usage:
#   scripts/run_timing_tests.sh              # full timing lane
#   scripts/run_timing_tests.sh <filter>...  # override the test filter list
#
# For best results run on an otherwise-idle machine, ideally with the chosen
# core excluded from general scheduling (isolcpus= / cset shield).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
export CARGO_TARGET_DIR="$TARGET_DIR"
export RUSTFLAGS="${RUSTFLAGS:-} --cfg franken_node_inline_tests"

# The timing-sensitive inline tests re-enabled under bd-m87xv.
DEFAULT_FILTERS=(
    control_plane::epoch_transition_barrier::epoch_transition_barrier_comprehensive_negative_tests::negative_timing_attack_resistance
    control_plane::divergence_gate::tests::negative_cryptographic_timing_hash_manipulation_and_side_channel_attacks
    security::threshold_sig::tests::negative_cryptographic_timing_attack_resistance_validation
    repair::tests::test_proof_verification_timing_consistency
    repair::tests::test_extreme_adversarial_fragment_timing_correlation_analysis
    supply_chain::revocation_registry::revocation_registry_comprehensive_negative_tests::negative_timing_attacks_revocation_checks
    policy::evidence_emission::tests::negative_timing_attacks_evidence_verification
    policy::hardening_state_machine::hardening_state_machine_comprehensive_negative_tests::negative_timing_attacks_governance_validation
    connector::execution_scorer::execution_scorer_comprehensive_negative_tests::negative_timing_attack_resistance
    perf::perf_module_extreme_adversarial_negative_tests::negative_timing_side_channel_resistance_in_proposal_evaluation
    perf::perf_module_extreme_adversarial_negative_tests::extreme_adversarial_timing_attack_via_proposal_id_length_correlation
)
if [ "$#" -gt 0 ]; then
    FILTERS=("$@")
else
    FILTERS=("${DEFAULT_FILTERS[@]}")
fi

echo "==> Building inline-lib-test binary (this can take a while)..."
cargo test -p frankenengine-node --lib --features extended-surfaces,test-support \
    --no-run --message-format=json \
    > "$TARGET_DIR/timing_lane_build.json" 2>"$TARGET_DIR/timing_lane_build.log" || {
    echo "Build failed; see $TARGET_DIR/timing_lane_build.log" >&2
    exit 1
}

TEST_BIN="$(python3 - "$TARGET_DIR/timing_lane_build.json" <<'EOF'
import json, sys
path = None
with open(sys.argv[1]) as fh:
    for line in fh:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") == "compiler-artifact" and msg.get("profile", {}).get("test"):
            target = msg.get("target", {})
            if target.get("name") in ("frankenengine-node", "frankenengine_node") and "lib" in target.get("kind", []):
                path = msg.get("executable") or path
print(path or "")
EOF
)"
if [ -z "$TEST_BIN" ] || [ ! -x "$TEST_BIN" ]; then
    echo "Could not locate the built lib test binary" >&2
    exit 1
fi
echo "==> Test binary: $TEST_BIN"

# Pick the isolation core: highest-numbered online CPU unless overridden.
CORE="${TIMING_TEST_CORE:-}"
if [ -z "$CORE" ]; then
    CORE="$(( $(nproc --all) - 1 ))"
fi
echo "==> Pinning to core $CORE (override with TIMING_TEST_CORE=<n>)"

# nice -n -5 sharpens scheduling if permitted; fall back silently if not.
NICE_PREFIX=(nice -n -5)
if ! "${NICE_PREFIX[@]}" true 2>/dev/null; then
    NICE_PREFIX=()
fi

echo "==> Running timing lane (FRANKEN_NODE_TIMING_TESTS=1, --test-threads=1)"
exec env FRANKEN_NODE_TIMING_TESTS=1 \
    taskset -c "$CORE" "${NICE_PREFIX[@]}" \
    "$TEST_BIN" --test-threads=1 --include-ignored --exact "${FILTERS[@]}"

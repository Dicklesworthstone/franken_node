#!/usr/bin/env bash
# TNR master mock-free pipeline lane (bd-f5b04.8.1).
#
# Runs the single-trace-id end-to-end harness that walks one real operation
# through every wired trust-native-runtime layer and prints a per-layer
# PASS/FAIL transcript:
#
#   L1 RUN     franken-node run (subprocess, in-process native engine)
#   L2 EFFECT  signed host-effect ledger (tamper-evident hash chain)
#   L3 LOG     ordered RUN-* structured-log events, one --trace-id
#   L4 REPLAY  incident bundle --verify -> replay -> counterfactual --policy strict
#   L5 VSDK    offline effect-chain re-derivation via frankenengine-verifier-sdk
#   L6 LTV     MMR root re-attestation + 2-of-3 witness cosign + anteriority
#
# Layers not yet wired into a live run (information-flow labels, Bayesian
# sentinel escalation, FN-EFFECT-*/FN-CAS-*/FN-TTR-* event emission, an LTV
# CLI surface) are tracked as beads and intentionally NOT simulated here; see
# the honest-scope header in crates/franken-node/tests/tnr_full_pipeline_e2e.rs.
#
# Usage:
#   scripts/run_tnr_full_pipeline.sh                 # full lane
#   scripts/run_tnr_full_pipeline.sh clean_run       # filter by test name
#
# Extra cargo-test filters/flags may be passed as arguments. The harness needs
# only the default feature set (engine); no network access beyond loopback.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

cargo test -p frankenengine-node --test tnr_full_pipeline_e2e "$@" -- --nocapture

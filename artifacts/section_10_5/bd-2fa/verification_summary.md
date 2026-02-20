# bd-2fa Verification Summary

## Outcome

Implemented deterministic counterfactual replay mode for policy simulation over incident replay bundles, including divergence analysis, sweep scenarios, and bounded execution guards.

## What Was Delivered

- Added `crates/franken-node/src/tools/counterfactual_replay.rs`:
  - `CounterfactualReplayEngine`
  - `PolicyConfig`
  - `DecisionPoint`, `DivergenceRecord`, `SummaryStatistics`, `CounterfactualResult`
  - `SimulationMode::{SinglePolicySwap, ParameterSweep}`
  - `SandboxedExecutor` + `PureSandboxedExecutor`
  - `ReplayExecutionBounds` with `max_replay_steps` and `max_wall_clock_millis`
  - partial-result bound errors for step/timeout limits
- Wired module export in `crates/franken-node/src/tools/mod.rs`.
- Replaced placeholder incident counterfactual branch in `crates/franken-node/src/main.rs` with engine-backed execution and canonical output.
- Added contract doc `docs/specs/section_10_5/bd-2fa_contract.md`.
- Added verifier and tests:
  - `scripts/check_counterfactual.py`
  - `tests/test_check_counterfactual.py`

## Validation

- PASS: `python3 scripts/check_counterfactual.py --json` (20/20)
- PASS: `python3 -m unittest tests/test_check_counterfactual.py` (10 tests)
- FAIL (environment/workspace): `rch exec -- cargo test --manifest-path crates/franken-node/Cargo.toml counterfactual_replay -- --nocapture`
  - remote worker path mirror does not include sibling workspace dependency `franken_engine`.
- FAIL (pre-existing workspace drift): `rch exec -- cargo fmt --manifest-path crates/franken-node/Cargo.toml --all --check`
  - broad formatting drift exists across unrelated files, including sibling `franken_engine` surfaces.
- FAIL (environment/workspace): `rch exec -- cargo check --manifest-path crates/franken-node/Cargo.toml --all-targets`
  - same remote sibling dependency resolution failure (`franken_engine` missing in remote mirror).
- FAIL (environment/workspace): `rch exec -- cargo clippy --manifest-path crates/franken-node/Cargo.toml --all-targets -- -D warnings`
  - same remote sibling dependency resolution failure (`franken_engine` missing in remote mirror).

## Notes

Cargo verification was executed via `rch` per policy. Current blockers are workspace/environmental (remote path-dependency mirroring + broad pre-existing formatting drift), not a counterfactual replay assertion failure.

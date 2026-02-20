# bd-2fa Contract: Counterfactual Replay Mode

## Scope

Implement deterministic, side-effect-free policy simulation over replay bundles from `bd-vll`, producing structured divergence evidence between original and counterfactual outcomes.

## Core Invariants

- `INV-CF-DETERMINISTIC`: same bundle + same policy inputs produce bit-identical outputs.
- `INV-CF-SANDBOXED`: replay execution is pure computation only (`SandboxedExecutor`).
- `INV-CF-BOUNDED`: replay enforces `max_replay_steps` and `max_wall_clock_millis`.

## Data Model

- `PolicyConfig`
  - `policy_name`
  - `quarantine_threshold`
  - `observe_threshold`
  - `degraded_mode_bias`
- `DecisionPoint`
  - `sequence_number`
  - `event_type`
  - `decision`
  - `rationale`
  - `expected_loss`
- `DivergenceRecord`
  - `sequence_number`
  - `original_decision`
  - `counterfactual_decision`
  - `original_rationale`
  - `counterfactual_rationale`
  - `impact_estimate`
- `CounterfactualResult`
  - `original_outcomes`
  - `counterfactual_outcomes`
  - `divergence_points`
  - `summary_statistics`
  - metadata (`bundle_hash`, override diff, replay timestamp, engine version)

## Engine API

- `CounterfactualReplayEngine::replay(bundle, alternate_policy)`
- `CounterfactualReplayEngine::replay_with_baseline(bundle, baseline_policy, alternate_policy)`
- `CounterfactualReplayEngine::simulate(bundle, baseline_policy, mode)`

### Simulation Modes

- `SinglePolicySwap`
- `ParameterSweep` (supports numeric parameter sweeps, max 20 values)

### Bounds and Errors

- `ReplayExecutionBounds`
  - `max_replay_steps` (default `100_000`)
  - `max_wall_clock_millis` (default `30_000`)
- On bound breach, engine returns typed errors with partial result payload:
  - `StepLimitExceeded`
  - `WallClockExceeded`

## CLI Contract (Current)

- `franken-node incident counterfactual --bundle <path> --policy <spec>`
  - `policy` supports:
    - profile names: `strict`, `balanced`, `permissive`
    - inline overrides: `key=value,key=value`
    - sweep: `sweep:<parameter>=v1|v2|...`

## Verification Contract

- Script: `scripts/check_counterfactual.py --json`
  - validates implementation/module/CLI wiring
  - runs single-policy-swap simulation and checks non-empty divergence
  - checks deterministic output stability
  - checks parameter sweep behavior
  - checks step/timeout guards with partial results
- Unit tests: `tests/test_check_counterfactual.py`
- Evidence artifacts:
  - `artifacts/section_10_5/bd-2fa/verification_evidence.json`
  - `artifacts/section_10_5/bd-2fa/verification_summary.md`

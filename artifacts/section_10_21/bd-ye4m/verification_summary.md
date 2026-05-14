# bd-ye4m - BPET Adversarial Evaluation Suite

## Verdict

`PASS` via `scripts/check_bpet_adversarial_evolution.py` (full `rch` cargo
proof). `PASS_STATIC_ONLY` is the alternate verdict surfaced when the gate
is run with `--skip-cargo` for checker unit tests.

## Gate

`scripts/check_bpet_adversarial_evolution.py` verifies the real bd-ye4m
implementation surface shipped by sub-tasks 1-4:

- `crates/franken-node/src/security/bpet/adversarial_evolution.rs` (ST1, 1217 LOC, 24 unit tests)
- `crates/franken-node/src/security/bpet/adversarial_harness.rs` (ST2, 1221 LOC, 13 unit tests)
- `crates/franken-node/src/security/bpet/adversarial_scenarios.rs` (ST3, 649 LOC, 11 unit tests)
- `tests/security/adversarial_scenarios/*.json` (ST3, 8 fixtures, one per `AdversaryKind`)
- `tests/security/bpet_adversarial_evolution_suite.rs` (ST4, 491 LOC, 13 integration tests)
- `docs/security/bpet_adversarial_playbook.md` (ST5, this gate, 182 LOC)
- `crates/franken-node/Cargo.toml` (test registration)

Cumulative test count: **61 tests** (24 + 13 + 11 + 13).

## Static Evidence

- `scenario_fixture_count` - exactly 8 JSON fixtures (one per `AdversaryKind` variant).
- `scenario_schema` - each fixture parses + matches `kind` / `ramp` / `expected_verdict.kind` invariants:
  - `SlowRollDrift` / `linear` / `caught_late`
  - `CapabilityCreepDisguisedAsFeature` / `sigmoid` / `caught_late`
  - `EvictionViaTrustFlooding` / `stepped` / `caught_early`
  - `ManyTinyUpdates` / `linear` / `missed_entirely`
  - `MultiPersonaCoordination` / `exponential` / `caught_early`
  - `FalseRecoveryClaim` / `stepped` / `caught_late`
  - `IndirectViaDep` / `sigmoid` / `caught_late`
  - `SignatureRollover` / `exponential` / `caught_early`
- `evolution_source` - LOC > 1000 and all 8 `AdversaryKind` + 4 `RampCurve` variants present.
- `harness_source` - LOC > 1000 and `run_scenario` + `AdversarialHarness` + `DetectorThresholds` + `ScenarioVerdict` + `DetectionVerdict` exported.
- `integration_suite` - 13 `#[test]`s in `bpet_adversarial_evolution_suite.rs`, registered in `Cargo.toml`.
- `playbook` - `docs/security/bpet_adversarial_playbook.md` documents all 8 adversary kinds, all 4 ramp curves, and `DetectorThresholds`.

## Required Full Proof

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/franken_node-crimsoncrane-bdye4m-target \
  cargo test -p frankenengine-node --test bpet_adversarial_evolution_suite -- --nocapture
```

Or, as a single command driving the gate:

```bash
python3 scripts/check_bpet_adversarial_evolution.py
```

# BPET Adversarial Evaluation Playbook

Bead: `bd-ye4m` (`bd-ye4m.1`)
Section: `10.21` (BPET — Behavioral Phenotype Evolution Tracker)
Status: shipped via sub-tasks 1-4; verification gated by
`scripts/check_bpet_adversarial_evolution.py` (sub-task 5).

## 1. Overview

The Behavioral Phenotype Evolution Tracker (BPET) watches packages, agents,
and capability surfaces evolve across time. Slow-roll attacks are the
hardest to catch precisely because any individual step looks benign — only
the *trajectory* gives the adversary away. The adversarial evaluation suite
exercises BPET against eight adversary archetypes, each paired with a
parametric ramp curve and a declared expected verdict, so regressions in
detector sensitivity show up as deterministic failures in
`tests/security/bpet_adversarial_evolution_suite.rs`.

Real types only, no mocks: every assertion runs through the production
`run_scenario` entry point. The eight on-disk JSON fixtures under
`tests/security/adversarial_scenarios/*.json` are byte-identical to the
in-code `synthesize_*` helpers (enforced by
`test_in_code_synthesizers_match_json_fixtures`).

## 2. Adversary Kinds (8)

Each kind is a variant of `AdversaryKind` in
`crates/franken-node/src/security/bpet/adversarial_evolution.rs`. The
fixture column matches the snake-case `as_str()` mapping, the verdict
column is the declared `ExpectedVerdict::kind` (mapped to a
`ScenarioVerdict` in `adversarial_harness.rs`), and the at-step window is
the inclusive `[at_step_lower, at_step_upper]` enforced by
`evaluate_scenario_fixture`. The three `ScenarioVerdict` variants
(`CaughtEarly`, `CaughtLate`, `MissedEntirely`) cover all outcomes.

| `AdversaryKind` | Fixture stem | `n_steps` | Ramp | Verdict band |
|---|---|---|---|---|
| `SlowRollDrift` | `slow_roll_drift` | 100 | Linear | `CaughtLate [60, 80]` |
| `CapabilityCreepDisguisedAsFeature` | `capability_creep_disguised_as_feature` | 80 | Sigmoid | `CaughtLate` |
| `EvictionViaTrustFlooding` | `eviction_via_trust_flooding` | 60 | Stepped | `CaughtEarly` |
| `ManyTinyUpdates` | `many_tiny_updates` | 200 | Linear | `MissedEntirely` |
| `MultiPersonaCoordination` | `multi_persona_coordination` | 50 | Exponential | `CaughtEarly` |
| `FalseRecoveryClaim` | `false_recovery_claim` | 40 | Stepped | `CaughtLate` |
| `IndirectViaDep` | `indirect_via_dep` | 60 | Sigmoid | `CaughtLate` |
| `SignatureRollover` | `signature_rollover` | 30 | Exponential | `CaughtEarly` |

### 2.1 `SlowRollDrift`

Drift-via-many-small-updates: a steady linear ramp publishes a small
declared capability increase while the adversary hides a 5% bonus on every
step. The detector should *not* fire in the first half — that would imply
overblocking on noise-level deltas. By construction the verdict band sits
at `CaughtLate [60, 80]`, so the drift detector dominates here.

### 2.2 `CapabilityCreepDisguisedAsFeature`

A new "feature" rolls out across plateaus that look indistinguishable from
a sigmoidal launch curve. The adversary banks on the regime-shift detector
treating the rollout as a legitimate baseline reset. Verdict band sits in
the late window because the sigmoid's inflection point only crosses the
combined-risk threshold past `n_steps / 2`.

### 2.3 `EvictionViaTrustFlooding`

A stepped ramp injects a burst of high-trust observations to displace the
prior baseline, then escalates capability under the fresh window. Hazard +
provenance detectors must catch the eviction *early* — the combined
threshold trips during the first stepped plateau (`CaughtEarly`).

### 2.4 `ManyTinyUpdates`

The pathological negative-control: 200 micro-perturbations each below the
combined threshold. The detector is *expected to miss* this scenario
(`MissedEntirely`) — it bounds the detector's recall floor and prevents
overfitting the thresholds to nuisance signals. If this fires, the
thresholds have been tuned too aggressively.

### 2.5 `MultiPersonaCoordination`

Colluding maintainer identities ramp synchronously along an exponential
curve. The provenance detector picks up the suspicious cross-persona
correlation in the first half — verdict band `CaughtEarly`.

### 2.6 `FalseRecoveryClaim`

Mid-campaign, the adversary publishes a "recovered baseline" announcement
in stepped plateaus to short-circuit detectors. The drift engine must
correctly weight the pre-recovery trajectory and not zero out its history;
verdict lands in the late window once the post-recovery escalation accrues
enough cumulative drift to exceed `DetectorThresholds::combined`.

### 2.7 `IndirectViaDep`

Capability escalates through a transitive dependency rather than the
package under test. The sigmoid ramp inflects late, hidden behind the
dep-graph edge. Verdict band `CaughtLate` because the indirect path
delays cumulative-divergence accumulation.

### 2.8 `SignatureRollover`

A maintainer key rolls; the adversary abuses the rollover to relaunder a
previously-flagged trajectory. Hazard + provenance detectors flag this on
the first post-rollover exponential ramp — verdict band `CaughtEarly`.

## 3. Ramp Curves (4)

Each curve is a variant of `RampCurve` in `adversarial_evolution.rs`. All
`f64` knobs are validated for finiteness and strict positivity by
`RampCurve::validate`. `value_at(step_idx, n_steps)` returns a value
clamped to `[0.0, 1.0]`.

| `RampCurve` | When to use | Parametric range | Mathematical form |
|---|---|---|---|
| `Linear` | Default for drift-style attacks; rules out curve-fitting in the threshold | — | `f(i) = i / (n - 1)` |
| `Exponential { base }` | Bursts that should trip detectors early | `base > 0`, `base != 1.0` | `(base^t - 1) / (base - 1)` |
| `Sigmoid { steepness }` | Inflected feature launches and trust-laundered escalations | `steepness > 0` | logistic centered at `n / 2` |
| `Stepped { plateau_count }` | Trust flooding and false-recovery patterns | `plateau_count >= 1` | step-function over `plateau_count` plateaus |

`Exponential` with `base == 1.0` is rejected at construction (it degenerates
to a constant; callers must use `Linear` explicitly).

## 4. `DetectorThresholds`

Defined in `crates/franken-node/src/security/bpet/adversarial_harness.rs`.
All five knobs are validated as finite and in `[0.0, 1.0]` by
`DetectorThresholds::try_new`.

| Field | `default_v1()` | Tuning rationale |
|---|---|---|
| `drift` | 0.20 | Trips on phenotype-vs-baseline divergence accumulated over the rolling window. Lowering increases recall on `SlowRollDrift` but risks firing on `ManyTinyUpdates`. |
| `regime_shift` | 0.30 | Trips on BOCPD-detected regime breaks. Tune up if `CapabilityCreepDisguisedAsFeature` overfires during the sigmoid inflection. |
| `hazard` | 0.30 | Survival-model hazard. Dominates `EvictionViaTrustFlooding` + `SignatureRollover`. |
| `provenance` | 0.40 | Maintainer/identity divergence. Dominates `MultiPersonaCoordination`. |
| `combined` | 0.25 | Unified risk score (post-weighting). The integration test wires per-scenario overrides via the fixture `thresholds` block — the playbook defaults are floors, not absolutes. |

Per-scenario thresholds are pinned in each fixture's `thresholds` block.
Drift on those values must be matched by an `expected_verdict` update; the
verification gate's `scenario_schema` check enforces `[0.0, 1.0]` validity
but not the tuning intent — that lives in this playbook.

## 5. Running the Suite

The full integration suite (one `#[test]` per `AdversaryKind` plus five
cross-cutting invariants — 13 tests total) runs through `rch`:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/franken_node-crimsoncrane-bdye4m-target \
  cargo test -p frankenengine-node --test bpet_adversarial_evolution_suite -- --nocapture
```

The verification gate wraps the same invocation and additionally checks
scenario fixture invariants, source LOC, and playbook coverage:

```bash
python3 scripts/check_bpet_adversarial_evolution.py            # full proof
python3 scripts/check_bpet_adversarial_evolution.py --skip-cargo  # static only
python3 scripts/check_bpet_adversarial_evolution.py --json --skip-cargo
python3 scripts/check_bpet_adversarial_evolution.py --self-test
```

The gate emits `artifacts/section_10_21/bd-ye4m/verification_evidence.json`
in the canonical `franken-node/verification-evidence/v1` schema (mirrors
`artifacts/section_10_20/bd-1q38/verification_evidence.json`).

## 6. References

Sub-task source-of-record (commit SHAs):

- ST1 `87dbad2a` — `crates/franken-node/src/security/bpet/adversarial_evolution.rs` (1217 LOC, 24 unit tests)
- ST2 `1ccf78ba` — `crates/franken-node/src/security/bpet/adversarial_harness.rs` (1221 LOC, 13 unit tests)
- ST3 `802350e9` — `crates/franken-node/src/security/bpet/adversarial_scenarios.rs` (649 LOC, 11 unit tests) + 8 JSON scenarios
- ST4 `caf223cc` — `tests/security/bpet_adversarial_evolution_suite.rs` (491 LOC, 13 integration tests)
- ST5 (this commit) — `scripts/check_bpet_adversarial_evolution.py` + `docs/security/bpet_adversarial_playbook.md` + `artifacts/section_10_21/bd-ye4m/`

Cumulative test count: **61 tests** (24 + 13 + 11 + 13).

Related artifacts:
- `tests/security/adversarial_scenarios/*.json` — 8 on-disk fixtures
- `artifacts/section_10_21/bd-ye4m/verification_evidence.json` — gate evidence
- `artifacts/section_10_21/bd-ye4m/verification_summary.md` — gate summary

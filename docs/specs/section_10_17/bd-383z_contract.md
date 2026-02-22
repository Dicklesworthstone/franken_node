# bd-383z Contract: Counterfactual Incident Lab and Mitigation Synthesis

**Section:** 10.17 -- Radical Expansion Execution Track
**Bead:** bd-383z
**Status:** In Progress
**Schema Version:** incident-lab-v1.0

## Overview

Build a counterfactual incident lab that replays real incident traces against
synthesized mitigations, computes expected-loss deltas, and produces signed
rollout/rollback contracts for promoted mitigations. The system supports
deterministic replay, Bayesian adversary modeling, and time-travel debugging
for post-incident analysis.

## Acceptance Criteria

1. Real incident traces can be replayed with reproducible outcomes.
2. Synthesized mitigations are compared against original traces with
   expected-loss deltas.
3. Promoted mitigations require signed rollout and rollback contracts.
4. The lab emits structured event codes (ILAB_001..ILAB_005+).
5. Error codes (ERR_ILAB_*) cover all failure modes.
6. Invariants (INV-ILAB-*) are documented and enforced.
7. Deterministic replay fixtures produce identical results across runs.
8. Machine-readable verification evidence with pass/fail verdict.

## Architecture

### Core Types

- **IncidentTrace** -- A recorded sequence of system events from a real incident.
- **CounterfactualScenario** -- A scenario combining an IncidentTrace with a
  candidate MitigationPlan for comparison.
- **MitigationPlan** -- A proposed mitigation with description, expected-loss
  reduction, and implementation steps.
- **IncidentReplay** -- A deterministic replay of a trace through the lab engine.
- **SynthesisResult** -- The outcome of comparing mitigated vs unmitigated
  replays, including expected-loss deltas.
- **RolloutContract** -- A signed contract authorizing deployment of a promoted
  mitigation, including rollback conditions.
- **IncidentLab** -- The top-level engine that orchestrates scenario evaluation.

### Event Codes

| Code      | Meaning                                       |
|-----------|-----------------------------------------------|
| ILAB_001  | Incident trace ingested into lab               |
| ILAB_002  | Counterfactual replay started                  |
| ILAB_003  | Expected-loss delta computed                   |
| ILAB_004  | Mitigation promoted (rollout contract signed)  |
| ILAB_005  | Mitigation rejected (delta below threshold)    |
| ILAB_006  | Rollback contract generated                    |

### Error Codes

| Code                         | Meaning                                   |
|------------------------------|-------------------------------------------|
| ERR_ILAB_TRACE_EMPTY         | Incident trace has no events              |
| ERR_ILAB_TRACE_CORRUPT       | Trace integrity check failed              |
| ERR_ILAB_REPLAY_DIVERGENCE   | Replay produced non-deterministic output  |
| ERR_ILAB_MITIGATION_INVALID  | MitigationPlan fails validation           |
| ERR_ILAB_DELTA_NEGATIVE      | Mitigation worsens expected loss          |
| ERR_ILAB_CONTRACT_UNSIGNED   | Rollout contract lacks required signature |

### Invariants

| ID                          | Statement                                               |
|-----------------------------|---------------------------------------------------------|
| INV-ILAB-DETERMINISTIC      | Replay of same trace always produces identical output    |
| INV-ILAB-DELTA-REQUIRED     | No promotion without computed expected-loss delta        |
| INV-ILAB-SIGNED-ROLLOUT     | Promoted mitigations require signed rollout contract     |
| INV-ILAB-ROLLBACK-ATTACHED  | Every rollout contract includes a rollback clause        |
| INV-ILAB-TRACE-INTEGRITY    | Traces are hash-verified before replay                  |

## Deliverables

- `docs/specs/section_10_17/bd-383z_contract.md` (this file)
- `crates/franken-node/src/runtime/incident_lab.rs`
- `scripts/check_incident_lab.py`
- `tests/test_check_incident_lab.py`
- `artifacts/section_10_17/bd-383z/verification_evidence.json`
- `artifacts/section_10_17/bd-383z/verification_summary.md`

## Testing Requirements

- 20+ inline Rust unit tests covering all invariants and error paths.
- Python checker script with `--json`, `--self-test`, `--build-report` flags.
- 12+ Python unit tests for the checker.
- Deterministic replay fixture: same input always produces same digest.

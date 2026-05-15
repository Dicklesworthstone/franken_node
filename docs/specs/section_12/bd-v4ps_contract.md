# bd-v4ps Contract: Temporal Concept Drift Risk Control

## Goal

Prevent stale trust/compatibility/threat models from making unsafe decisions by enforcing model TTLs, cohort drift audits, and mandatory recalibration triggers.

## Quantified Invariants

- `INV-TCD-TTL`: Every model has explicit TTL and last-calibration timestamp metadata.
- `INV-TCD-STALE-BLOCK`: Models past TTL are flagged stale and blocked from deployment decisions.
- `INV-TCD-DRIFT-GATE`: If recent 30-day cohort accuracy degrades by more than `5%` versus all-time baseline, recalibration is triggered.
- `INV-TCD-RECAL-PIPELINE`: Recalibration pipeline evidence reports deterministic status and explicitly distinguishes fixture replay from live recalibration. Synthetic fixture evidence must carry a fixture-only classification, source-path evidence, and passing verifier commands; it must not be cited as live recalibration proof.
- `INV-TCD-COHORT-REPORT`: Accuracy is reported by monthly cohort to expose temporal drift patterns.

## Determinism Requirements

- Re-running verification on identical drift report input yields identical verdict.
- Model ordering does not affect aggregate TTL/drift decisions.
- Adversarial perturbation that disables stale-model blocking deterministically flips gate result to fail.

## Required Scenarios

1. Scenario A: TTL set to 1 day and model age advanced to 2 days triggers staleness alert and deployment block.
2. Scenario B: Inject concept drift; accuracy delta exceeds 5% and triggers recalibration.
3. Scenario C: Recalibration run improves recent-cohort accuracy.
4. Scenario D: Accuracy is reported for each monthly cohort.

## Structured Event Codes

- `TCD-001`: Model freshness evaluated.
- `TCD-002`: Staleness alert emitted and deployment blocked.
- `TCD-003`: Drift delta evaluated against threshold.
- `TCD-004`: Recalibration pipeline evidence completed with explicit fixture/live classification.
- `TCD-005`: Cohort audit report generated.

All events must include stable `trace_id`, `model_id`, and cohort context.

## Machine-Readable Artifacts

- `artifacts/12/temporal_concept_drift_report.json`
- `artifacts/section_12/bd-v4ps/verification_evidence.json`
- `artifacts/section_12/bd-v4ps/verification_summary.md`

## Acceptance Mapping

- Countermeasure (a): continuous recalibration is enforced through TTL+drift trigger contracts.
- Countermeasure (b): cohort-specific drift audits are required via all-time vs recent cohort deltas.
- Countermeasure (c): staleness alerts become blocking gates for deployment decisions.

# bd-v4ps Verification Summary

- Bead: `bd-v4ps`
- Section: `12`
- Capability: `Risk control: temporal concept drift`
- Verdict: `PASS`

## Scope Delivered

- Contract specification: `docs/specs/section_12/bd-v4ps_contract.md`
- Machine-readable report: `artifacts/12/temporal_concept_drift_report.json`
- Verifier: `scripts/check_temporal_concept_drift.py`
- Unit tests: `tests/test_check_temporal_concept_drift.py`

## Acceptance Results

- Every model includes TTL and last-calibration timestamp metadata.
- Stale models are flagged and deployment-blocked.
- Drift detection compares recent 30-day cohort accuracy against all-time baseline; deltas above `5%` trigger recalibration.
- Recalibration pipeline evidence is explicitly fixture-only, source-backed, and command-backed; synthetic fixture replay is not cited as live recalibration proof.
- Monthly cohort accuracy breakdown is present for temporal auditability.

## Scenario Coverage

- Scenario A: TTL-expired model triggers staleness alert and deployment block.
- Scenario B: injected concept drift (`>5%`) triggers recalibration.
- Scenario C: recalibration improves recent cohort accuracy.
- Scenario D: monthly cohort breakdown is reported.

## Determinism and Adversarial Validation

- Model-order-insensitive aggregate evaluation is stable.
- Adversarial stale-model unblock attempt is detected by verifier.
- Tampered pipeline evidence fails closed when execution mode, live-claim guard, source paths, or recorded passing commands are missing.

## Reproducible Commands

```bash
python3 scripts/check_temporal_concept_drift.py --self-test --json
python3 scripts/check_temporal_concept_drift.py --json
python3 -m unittest tests/test_check_temporal_concept_drift.py
```

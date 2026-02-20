# bd-33b: Expected-Loss Action Scoring with Explicit Loss Matrices

## Bead: bd-33b | Section: 10.5

## Purpose

Provide deterministic, auditable expected-loss scoring for policy actions.
The scorer consumes an explicit action/outcome loss matrix and probability
vector, returns per-action expected loss breakdowns, and supports rank-change
sensitivity analysis under probability perturbations.

## Invariants

| ID | Statement |
|----|-----------|
| INV-ELS-MATRIX-EXPLICIT | Every action/outcome pair has an explicit numeric loss entry. |
| INV-ELS-PROBABILITY-VALID | State probabilities must be finite, within `[0,1]`, and sum to `1.0 ± 1e-9`. |
| INV-ELS-DETERMINISTIC | Identical inputs produce identical expected-loss values and ranking order. |
| INV-ELS-SORT-ASC | `compare_actions` orders by expected loss ascending (lowest expected loss first). |
| INV-ELS-SENSITIVITY | Sensitivity output reports rank changes with `(parameter_name, delta, original_rank, perturbed_rank)`. |
| INV-ELS-SCHEMA-VERSIONED | Loss matrices are JSON-serializable and carry `schema_version`. |

## Types

### `LossMatrix`
- `schema_version: String`
- `actions: Vec<String>`
- `outcomes: Vec<String>`
- `values: Vec<Vec<f64>>` (row-major, `actions x outcomes`)

Validation requirements:
- non-empty `schema_version`
- non-empty actions and outcomes
- row count equals action count
- each row length equals outcome count
- finite numeric values only
- action set includes `do_nothing` (or `do nothing`/`noop` equivalent)

### `ExpectedLossScore`
- `action: String`
- `expected_loss: f64`
- `dominant_outcome: String`
- `breakdown: Vec<(String, f64)>` (outcome -> weighted contribution)

### `SensitivityRecord`
- `action: String`
- `parameter_name: String`
- `delta: f64`
- `original_rank: usize`
- `perturbed_rank: usize`

## API Surface

- `score_action(action, loss_matrix, state_probabilities) -> Result<ExpectedLossScore, LossScoringError>`
- `compare_actions(actions, matrix, probs) -> Result<Vec<ExpectedLossScore>, LossScoringError>`
- `sensitivity_analysis(actions, matrix, probs, delta) -> Result<Vec<SensitivityRecord>, LossScoringError>`
- `sensitivity_analysis_default(actions, matrix, probs) -> Result<Vec<SensitivityRecord>, LossScoringError>`

## Error Codes

| Code | Trigger |
|------|---------|
| `ELS_INVALID_SCHEMA` | Invalid matrix shape or invalid schema fields. |
| `ELS_MISSING_DO_NOTHING_ACTION` | Matrix does not contain a `do_nothing` action row. |
| `ELS_UNKNOWN_ACTION` | Requested action not found in matrix action list. |
| `ELS_PROBABILITY_LENGTH_MISMATCH` | Probability vector length does not match outcome count. |
| `ELS_INVALID_PROBABILITIES` | Probability vector has invalid range/sum/NaN values. |
| `ELS_NO_ACTIONS_REQUESTED` | `compare_actions` called with empty action set. |
| `ELS_INVALID_SENSITIVITY_DELTA` | Sensitivity delta is non-finite or non-positive. |

## Expected Artifacts

| Artifact | Path |
|----------|------|
| Rust implementation | `crates/franken-node/src/connector/execution_scorer.rs` |
| Verification script | `scripts/check_loss_scoring.py` |
| Verification unit tests | `tests/test_check_loss_scoring.py` |
| Verification evidence | `artifacts/section_10_5/bd-33b/verification_evidence.json` |
| Verification summary | `artifacts/section_10_5/bd-33b/verification_summary.md` |

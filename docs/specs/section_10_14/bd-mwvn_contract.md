# bd-mwvn: Policy Action Explainer

**Section**: 10.14
**Module**: `crates/franken-node/src/policy/policy_explainer.rs`
**Depends on**: bd-15u3 (guardrail precedence / DecisionOutcome), bd-2igi (BayesianDiagnostics)

## Overview

The policy explainer produces structured output that explicitly separates
diagnostic confidence (heuristic, data-driven, from Bayesian posterior) from
guarantee confidence (provable, guardrail-backed, from invariant verification).
Operators are never misled into treating a strong recommendation as a hard safety guarantee.

## Confidence Types

| Type | Source | Meaning |
|------|--------|---------|
| Diagnostic | Bayesian posterior (bd-2igi) | "Data suggests this action" |
| Guarantee | Guardrail monitors (bd-3a3q) | "This action is provably safe" |

## Types

| Type | Purpose |
|------|---------|
| `PolicyExplainer` | Stateless explainer that produces structured explanations |
| `PolicyExplanation` | Complete explanation with both confidence sections |
| `DiagnosticSection` | Bayesian posterior, observation count, CI, summary |
| `GuaranteeSection` | Guardrail pass/fail, invariants verified, summary |
| `BlockedExplanation` | Why a higher-ranked alternative was blocked |
| `WordingValidation` | Result of vocabulary separation check |

## Wording Rules

- Diagnostic section uses: "statistically suggested", "data indicates",
  "heuristic estimate", "posterior probability", "observation-based"
- Guarantee section uses: "verified by guardrail", "proven within bounds",
  "guaranteed by invariant", "provably safe", "formally verified"
- Cross-contamination is rejected by `validate_wording()`.

## Event Codes

| Code | Trigger |
|------|---------|
| EVD-EXPLAIN-001 | Explanation generated |
| EVD-EXPLAIN-002 | Wording validation passed |
| EVD-EXPLAIN-003 | Wording validation failed |
| EVD-EXPLAIN-004 | Explanation serialized for API |

## Invariants

| ID | Description |
|----|-------------|
| INV-EXPLAIN-SEPARATION | Diagnostic and guarantee sections always distinct |
| INV-EXPLAIN-WORDING | No cross-vocabulary contamination |
| INV-EXPLAIN-COMPLETE | Both sections present even with no data |

## Capabilities

- Generates `PolicyExplanation` from any `DecisionOutcome` + `BayesianDiagnostics`
- Validates wording separation via `validate_wording()` (EVD-EXPLAIN-002/003)
- Serializes explanations to JSON via `PolicyExplainer::to_json()` (EVD-EXPLAIN-004)
- Works with zero observations (INV-EXPLAIN-COMPLETE: always produces both sections)

## Artifacts

| Artifact | Path |
|----------|------|
| Implementation | `crates/franken-node/src/policy/policy_explainer.rs` |
| Spec contract | `docs/specs/section_10_14/bd-mwvn_contract.md` |
| Verification script | `scripts/check_policy_explainer.py` |
| Python unit tests | `tests/test_check_policy_explainer.py` |
| Example explanations | `artifacts/10.14/policy_explainer_examples.json` |
| Verification evidence | `artifacts/section_10_14/bd-mwvn/verification_evidence.json` |
| Verification summary | `artifacts/section_10_14/bd-mwvn/verification_summary.md` |

## Dependencies

- **Upstream**: bd-15u3 (decision engine provides DecisionOutcome), bd-2igi (BayesianDiagnostics)
- **Downstream**: bd-3epz (section gate), bd-5rh (plan gate)

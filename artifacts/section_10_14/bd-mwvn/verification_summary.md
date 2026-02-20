# bd-mwvn: Verification Summary

## Policy Action Explainer (Diagnostic vs Guarantee Confidence)

**Section:** 10.14 (FrankenSQLite Deep-Mined Expansion)
**Status:** PASS (61/61 checks)
**Agent:** CrimsonCrane (claude-code, claude-sonnet-4-6)
**Date:** 2026-02-20

## Implementation

- **Module:** `crates/franken-node/src/policy/policy_explainer.rs`
- **Spec:** `docs/specs/section_10_14/bd-mwvn_contract.md`
- **Verification:** `scripts/check_policy_explainer.py`
- **Test Suite:** `tests/test_check_policy_explainer.py` (24 tests)
- **Examples Artifact:** `artifacts/10.14/policy_explainer_examples.json` (5 scenarios)

## Architecture

| Type | Purpose |
|------|---------|
| `PolicyExplainer` | Produces structured explanations from DecisionOutcome + BayesianDiagnostics |
| `PolicyExplanation` | Complete explanation with separate diagnostic and guarantee sections |
| `DiagnosticSection` | Posterior, observation count, CI, heuristic language |
| `GuaranteeSection` | Guardrail pass/fail, invariants verified, guarantee language |
| `BlockedExplanation` | Why a higher-ranked alternative was blocked |
| `WordingValidation` | Validates vocabulary separation between sections |

## Key Properties

- **Vocabulary separation**: Guarantee terms forbidden in diagnostic text and vice versa
- **Always complete**: Both sections present even with zero observations
- **Wording validation**: `validate_wording()` callable independently for CI
- **Serialization**: JSON API includes both sections as top-level fields

## Event Codes

| Code | Trigger |
|------|---------|
| EVD-EXPLAIN-001 | Explanation generated |
| EVD-EXPLAIN-002 | Wording validation passed |
| EVD-EXPLAIN-003 | Wording validation failed |
| EVD-EXPLAIN-004 | Explanation serialized for API |

## Invariants

| ID | Status |
|----|--------|
| INV-EXPLAIN-SEPARATION | Verified — both sections are required struct fields in PolicyExplanation |
| INV-EXPLAIN-WORDING | Verified — GUARANTEE_VOCABULARY and DIAGNOSTIC_VOCABULARY are disjoint; validate_wording() enforces separation |
| INV-EXPLAIN-COMPLETE | Verified — zero-observation outcomes still produce populated DiagnosticSection |

## Example Scenarios

| Scenario | Diagnostic | Guarantee |
|----------|------------|-----------|
| all-guardrails-pass | high (many obs) | all passed |
| top-candidate-blocked (fallback) | medium | chosen verified, top blocked |
| all-blocked | high (obs, no selection) | none safe |
| high-diagnostic-low-guarantee | high posterior | durability guardrail blocks |
| low-diagnostic-high-guarantee | few observations | all guardrails pass |

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

## Test Summary

| Category | Count | Status |
|----------|-------|--------|
| Rust unit tests | 35 | All pass |
| Python verification checks | 61 | All pass |
| Python unit tests | 24 | All pass |

## Downstream Unblocked

- bd-3epz: Section 10.14 verification gate
- bd-5rh: 10.14 plan gate

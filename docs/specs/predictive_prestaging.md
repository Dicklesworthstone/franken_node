# Predictive Pre-staging Specification

This file preserves the plan-level artifact path for bd-2t5u and points to
the canonical implementation contract.

## Canonical Contract

- Spec: `docs/specs/section_10_13/bd-2t5u_contract.md`
- Implementation: `crates/franken-node/src/connector/prestage_engine.rs`
- Integration tests: `tests/integration/prestaging_coverage_improvement.rs`
- Verification gate: `scripts/check_prestage_engine.py`
- Evidence: `artifacts/section_10_13/bd-2t5u/verification_evidence.json`

## Required Invariants

- **INV-PSE-BUDGET**: Pre-staged bytes remain within the configured budget.
- **INV-PSE-COVERAGE**: Staging decisions improve offline coverage over the
  no-prestaging baseline.
- **INV-PSE-DETERMINISTIC**: The same candidates and configuration produce the
  same decision order and staging verdicts.
- **INV-PSE-QUALITY**: Precision, recall, and F1 quality metrics are measured.

The registered Rust coverage is intentionally under `tests/integration/`
because the current proof exercises the real pre-staging engine API rather than
a standalone performance harness.

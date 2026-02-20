# bd-novi Verification Summary

## Bead
**bd-novi** — Stable error code namespace with machine-readable retryable/retry_after/recovery_hint contract

## Verdict: PASS

All 6 verification checks passed.

| Check | Description | Status |
|-------|-------------|--------|
| ECR-IMPL | Implementation with all required types | PASS |
| ECR-ERRORS | All 5 error codes present (5/5) | PASS |
| ECR-CATALOG | Error code registry fixture | PASS |
| ECR-INTEG | Integration tests cover all 4 invariants | PASS |
| ECR-TESTS | Rust unit tests pass (17 passed) | PASS |
| ECR-SPEC | Specification with invariants and types | PASS |

## Artifacts
- Spec: `docs/specs/section_10_13/bd-novi_contract.md`
- Impl: `crates/franken-node/src/connector/error_code_registry.rs`
- Integration tests: `tests/integration/error_contract_stability.rs`
- Error catalog: `artifacts/section_10_13/bd-novi/error_code_registry.json`
- Verification script: `scripts/check_error_code_registry.py`
- Python tests: `tests/test_check_error_code_registry.py` (13 passed)
- Evidence: `artifacts/section_10_13/bd-novi/verification_evidence.json`

## Invariants Covered
- **INV-ECR-NAMESPACED** — All codes start with FRANKEN_{SUBSYSTEM}_ prefix
- **INV-ECR-UNIQUE** — No duplicate codes allowed in registry
- **INV-ECR-RECOVERY** — Non-fatal errors carry retryable/retry_after_ms/recovery_hint
- **INV-ECR-FROZEN** — Frozen codes cannot change severity or recovery semantics

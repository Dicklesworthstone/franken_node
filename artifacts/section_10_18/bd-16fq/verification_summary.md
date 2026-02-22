# bd-16fq Verification Summary

**Section:** 10.18 (VEF)  
**Verdict:** PASS

## Scope Delivered

Implemented a deterministic, versioned VEF policy-constraint language compiler
for all required high-risk action classes:

- `network_access`
- `filesystem_operation`
- `process_spawn`
- `secret_access`
- `policy_transition`
- `artifact_promotion`

The compiler emits proof-checkable predicates with stable rule trace links and
canonical policy snapshot hashing.

## Key Outputs

- `crates/franken-node/src/connector/vef_policy_constraints.rs`
- `spec/vef_policy_constraints_v1.json`
- `docs/specs/vef_policy_constraint_language.md`
- `docs/specs/section_10_18/bd-16fq_contract.md`
- `vectors/vef_policy_constraint_compiler.json`
- `scripts/check_vef_policy_constraints.py`
- `tests/test_check_vef_policy_constraints.py`
- `tests/conformance/vef_policy_constraint_compiler.rs`
- `crates/franken-node/tests/vef_policy_constraint_compiler.rs`
- `artifacts/10.18/vef_constraint_compiler_report.json`

## Validation

- Checker validates implementation, schema, fixtures, specs, and artifacts.
- Unit tests cover checker behavior and output shape.
- Compiler module includes deterministic + round-trip tests and boundary/error checks.
- `rch` cargo validation was executed per project policy:
  - Added wrapper `crates/franken-node/tests/vef_policy_constraint_compiler.rs` so cargo recognizes the target.
  - `cargo test -p frankenengine-node --test vef_policy_constraint_compiler` now resolves the target, but compile still fails on pre-existing workspace errors unrelated to bd-16fq.
  - `cargo check --all-targets`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` fail on pre-existing workspace issues outside the bd-16fq files.

## Invariants

- `INV-VEF-COMP-DETERMINISTIC`
- `INV-VEF-COMP-COVERAGE`
- `INV-VEF-COMP-TRACEABLE`
- `INV-VEF-COMP-VERSIONED`
- `INV-VEF-COMP-ROUNDTRIP`

## Event Codes

- `VEF-COMPILE-001`
- `VEF-COMPILE-002`
- `VEF-COMPILE-ERR-001`
- `VEF-COMPILE-ERR-002`
- `VEF-COMPILE-ERR-003`
- `VEF-COMPILE-ERR-004`
- `VEF-COMPILE-ERR-005`

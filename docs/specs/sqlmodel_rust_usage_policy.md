# sqlmodel_rust Usage Policy (`bd-bt82`)

## Purpose

This policy defines where `sqlmodel_rust` typed models are mandatory, should-use, or optional across `franken_node` persistence domains.

The policy exists to ensure schema drift is caught before runtime and to make model ownership and codegen/versioning auditable.

## Scope

- Applies to persistence domains listed in `artifacts/10.16/frankensqlite_persistence_matrix.json`.
- Governs typed model ownership, generation strategy, versioning, and drift detection.
- Serves as the policy input for downstream integration (`bd-1v65`) and 10.16 section gate checks.

## Classification Policy

Classifications:
- `mandatory`: typed model required before merge.
- `should_use`: typed model strongly preferred; temporary waiver allowed with explicit rationale.
- `optional`: typed model may be skipped for ephemeral/recomputable domains.

Minimum mandatory categories in this policy include:
- Control state (fencing, leases, rollout, channel state)
- Audit logs and decision journals
- Schema migration metadata

## Model Ownership Rules

- Each typed model has exactly one owner module.
- A model cannot be co-owned by multiple modules.
- Cross-module access must occur through owner-defined interfaces; direct struct mutation across module boundaries is disallowed.
- Ownership declarations live in `artifacts/10.16/sqlmodel_policy_matrix.json` (`ownership_rules`).

## Codegen and Versioning Expectations

- Model source is explicit per domain: `hand_authored` or `codegen`.
- All mandatory domains require explicit semantic model versions (`major.minor.patch`).
- Breaking schema/model changes require a major version bump.
- `codegen` domains must declare schema source and regeneration policy.
- Stale generated models are warning-level initially and become gate-failing when schema major versions diverge.

## Schema Drift Detection

Drift detection is validated by the policy verifier and consumed by downstream conformance work (`bd-1v65`):
- Every persistence domain from `bd-1a1j` must exist in this policy matrix.
- Mandatory domains must have `typed_model_defined=true` and a non-empty `model_name`.
- Ownership uniqueness is enforced over `model_name` and `ownership_rules`.
- Drift signals are emitted when new persistence domains appear without classification.

## Boundary with frankensqlite

- `sqlmodel_rust`: typed Rust model layer (structs, field types, query contracts, compile-time guarantees).
- `frankensqlite`: storage engine layer (durability mode, WAL behavior, transaction semantics, recovery mechanics).
- Boundary rule: model changes do not implicitly alter storage durability; storage mode changes do not bypass typed-model validation.

## Event Codes

- `SQLMODEL_POLICY_LOADED` (info)
- `SQLMODEL_DOMAIN_UNCLASSIFIED` (error)
- `SQLMODEL_OWNERSHIP_CONFLICT` (error)
- `SQLMODEL_CODEGEN_STALE` (warning)

All events include `trace_correlation` as SHA-256 over canonical policy-matrix JSON.

## Artifact Linkage

- `artifacts/10.16/sqlmodel_policy_matrix.json`
- `scripts/check_sqlmodel_policy.py`
- `tests/test_check_sqlmodel_policy.py`
- `artifacts/section_10_16/bd-bt82/verification_evidence.json`
- `artifacts/section_10_16/bd-bt82/verification_summary.md`

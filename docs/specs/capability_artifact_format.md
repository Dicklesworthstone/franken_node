# Capability-Carrying Extension Artifact Format (bd-3ku8)

## Scope

This contract defines the admission and runtime enforcement protocol for
capability-carrying extension artifacts in `franken_node`. Every extension
artifact must carry an embedded capability contract that declares the exact
set of capabilities the extension requires. Admission is **fail-closed**:
missing or invalid capability contracts cause immediate rejection. At runtime,
the enforced capability envelope must match the admitted contract without drift.

## Core Invariants

- `INV-ARTIFACT-FAIL-CLOSED`: artifact admission denies any artifact whose capability contract is absent, malformed, or fails validation.
- `INV-ARTIFACT-CAPABILITY-ENVELOPE`: the runtime capability envelope exactly matches the admitted capability set; no capability outside the contract is accessible.
- `INV-ARTIFACT-NO-DRIFT`: runtime enforcement continuously verifies that the active capability set has not drifted from the admitted contract.
- `INV-ARTIFACT-SIGNED-CONTRACT`: capability contracts must carry a valid signature from a trusted signer.

## Admission Rules

1. Artifact must contain a `capability_contract` field.
2. Capability contract must include `contract_id`, `extension_id`, `capabilities`, `signer_id`, `signature`, and `schema_version`.
3. Every capability entry must specify `capability_id`, `scope`, and `max_calls_per_epoch`.
4. Contract signature must verify against a trusted signer.
5. Contract `schema_version` must match the expected admission schema.
6. If any rule fails, admission is denied (fail-closed).

## Enforcement Rules

1. At runtime, the enforced capability set is the intersection of the admitted contract capabilities and the runtime policy.
2. Any capability invocation outside the admitted envelope triggers an enforcement violation.
3. Periodic drift checks compare the active capability set against the admitted contract.
4. Drift detection triggers an immediate enforcement event and optional quarantine.

## Capability Contract Schema

Required fields:

- `contract_id`
- `extension_id`
- `capabilities` (array of `CapabilityEntry`)
- `signer_id`
- `signature`
- `schema_version`
- `issued_epoch_ms`

### CapabilityEntry

- `capability_id`
- `scope` (e.g., `"filesystem:read"`, `"network:egress"`)
- `max_calls_per_epoch`

## Event Codes

- `ARTIFACT_ADMISSION_START`
- `ARTIFACT_CAPABILITY_VALIDATED`
- `ARTIFACT_ADMISSION_ACCEPTED`
- `ARTIFACT_ENFORCEMENT_CHECK`
- `ARTIFACT_DRIFT_DETECTED`

## Error Codes

- `ERR_ARTIFACT_MISSING_CONTRACT`
- `ERR_ARTIFACT_INVALID_CAPABILITY`
- `ERR_ARTIFACT_SIGNATURE_INVALID`
- `ERR_ARTIFACT_SCHEMA_MISMATCH`
- `ERR_ARTIFACT_ENFORCEMENT_DRIFT`
- `ERR_ARTIFACT_ADMISSION_DENIED`

## Required Artifacts

- `crates/franken-node/src/extensions/artifact_contract.rs`
- `crates/franken-node/src/extensions/mod.rs`
- `tests/conformance/capability_artifact_admission.rs`
- `artifacts/10.17/capability_artifact_vectors.json`
- `artifacts/section_10_17/bd-3ku8/verification_evidence.json`
- `artifacts/section_10_17/bd-3ku8/verification_summary.md`

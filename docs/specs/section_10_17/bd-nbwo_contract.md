# bd-nbwo: Universal Verifier SDK and Replay Capsule Format

**Section:** 10.17 -- Radical Expansion Execution Track
**Status:** In Progress
**Owner:** CrimsonCrane

## Objective

Publish a universal verifier SDK and replay capsule format that enables external
verifiers to replay signed capsules and reproduce claim verdicts without
privileged internal access. The capsule schema and verification APIs must be
stable and versioned.

## Acceptance Criteria

1. External verifiers can replay signed capsules and reproduce claim verdicts
   without privileged internal access.
2. Capsule schema and verification APIs are stable and versioned
   (`VSDK_SCHEMA_VERSION = "vsdk-v1.0"`).
3. All types are `Send + Sync`, serializable via serde, and use `BTreeMap` for
   deterministic ordering.
4. Event codes VSDK_001..VSDK_007 are defined for audit telemetry.
5. Error codes ERR_VSDK_* (7 codes) cover all failure modes.
6. Five invariants (INV-VSDK-*) are documented and enforced in code.
7. Minimum 20 inline `#[cfg(test)]` unit tests.

## Module: `connector::universal_verifier_sdk`

### Types

| Type                  | Purpose                                         |
|-----------------------|-------------------------------------------------|
| `CapsuleVerdict`      | Enum: Pass, Fail, Inconclusive                  |
| `CapsuleManifest`     | Describes capsule contents and expected outputs  |
| `ReplayCapsule`       | Signed, self-contained replay unit               |
| `ReplayResult`        | Outcome of replaying a capsule                   |
| `SessionStep`         | Single step in a verification session            |
| `VerificationSession` | Stateful multi-step verification workflow         |
| `VerifierSdk`         | Top-level facade for external verifiers          |
| `VsdkEvent`           | Structured audit event                           |
| `VsdkError`           | Error type with ERR_VSDK_* codes                 |

### Event Codes

| Code      | Meaning                          |
|-----------|----------------------------------|
| VSDK_001  | Capsule replay started           |
| VSDK_002  | Capsule replay completed (PASS)  |
| VSDK_003  | Capsule replay completed (FAIL)  |
| VSDK_004  | Verification session created     |
| VSDK_005  | Verification session step added  |
| VSDK_006  | Capsule signature verified       |
| VSDK_007  | Capsule manifest validated       |

### Error Codes

| Code                        | Meaning                              |
|-----------------------------|--------------------------------------|
| ERR_VSDK_CAPSULE_INVALID    | Capsule structure is invalid         |
| ERR_VSDK_SIGNATURE_MISMATCH | Signature does not match payload     |
| ERR_VSDK_SCHEMA_UNSUPPORTED | Schema version not supported         |
| ERR_VSDK_REPLAY_DIVERGED    | Replay output diverges from expected |
| ERR_VSDK_SESSION_SEALED     | Session is sealed, no more steps     |
| ERR_VSDK_MANIFEST_INCOMPLETE| Manifest missing required fields     |
| ERR_VSDK_EMPTY_PAYLOAD      | Capsule payload is empty             |

### Invariants

| ID                           | Description                                |
|------------------------------|--------------------------------------------|
| INV-VSDK-CAPSULE-DETERMINISTIC | Same capsule always produces same verdict |
| INV-VSDK-NO-PRIVILEGE        | No privileged internal access required     |
| INV-VSDK-SCHEMA-VERSIONED    | Every capsule carries schema version       |
| INV-VSDK-SESSION-MONOTONIC   | Session steps are append-only              |
| INV-VSDK-SIGNATURE-BOUND     | Signature covers full capsule payload      |

### Core Operations

- `validate_manifest(manifest)` -- validate capsule manifest completeness
- `verify_capsule_signature(capsule)` -- verify capsule signature integrity
- `sign_capsule(capsule)` -- compute and set capsule signature
- `replay_capsule(capsule, verifier_identity)` -- replay and produce verdict
- `create_session(id, verifier)` -- create new verification session
- `record_session_step(session, result)` -- append replay result to session
- `seal_session(session)` -- seal session and compute final verdict
- `create_verifier_sdk(verifier)` -- create SDK facade instance

## Dependencies

- bd-2iyk: Information-flow lineage and exfiltration sentinel
- bd-1xbc: Deterministic time-travel runtime capture/replay

## Deliverables

- `crates/franken-node/src/connector/universal_verifier_sdk.rs`
- `docs/specs/section_10_17/bd-nbwo_contract.md`
- `scripts/check_universal_verifier_sdk.py`
- `tests/test_check_universal_verifier_sdk.py`
- `artifacts/section_10_17/bd-nbwo/verification_evidence.json`
- `artifacts/section_10_17/bd-nbwo/verification_summary.md`

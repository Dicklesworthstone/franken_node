# bd-nbwo: Universal Verifier SDK and Replay Capsule Format

**Section:** 10.17 -- Radical Expansion Execution Track
**Verdict:** PASS

## Summary

This bead publishes a universal verifier SDK and replay capsule format that
enables external verifiers to replay signed capsules and reproduce claim
verdicts without privileged internal access. The capsule schema (`vsdk-v1.0`)
and verification APIs are stable and versioned.

## Deliverables

| Deliverable                | Path                                                               | Status |
|----------------------------|--------------------------------------------------------------------|--------|
| Replay capsule spec        | `docs/specs/replay_capsule_format.md`                              | PASS   |
| Bead contract              | `docs/specs/section_10_17/bd-nbwo_contract.md`                     | PASS   |
| Implementation (Rust)      | `crates/franken-node/src/connector/universal_verifier_sdk.rs`      | PASS   |
| SDK facade (mod.rs)        | `sdk/verifier/mod.rs`                                              | PASS   |
| SDK facade (capsule.rs)    | `sdk/verifier/capsule.rs`                                          | PASS   |
| Conformance test           | `tests/conformance/verifier_sdk_capsule_replay.rs`                 | PASS   |
| Gate script                | `scripts/check_verifier_sdk_capsule.py`                            | PASS   |
| Unit test suite            | `tests/test_check_verifier_sdk_capsule.py`                         | PASS   |
| Certification report       | `artifacts/10.17/verifier_sdk_certification_report.json`           | PASS   |

## Implementation

**Module:** `crates/franken-node/src/connector/universal_verifier_sdk.rs`

### Types (9)

- `CapsuleVerdict` -- Enum: Pass, Fail, Inconclusive
- `CapsuleManifest` -- Describes capsule contents, schema version, expected outputs
- `ReplayCapsule` -- Signed, self-contained replay unit with deterministic inputs/outputs
- `ReplayResult` -- Outcome of replaying a capsule
- `SessionStep` -- Single step in a multi-step verification session
- `VerificationSession` -- Stateful session for multi-step verification workflows
- `VerifierSdk` -- Top-level facade for external verifiers
- `VsdkEvent` -- Structured audit event for telemetry
- `VsdkError` -- Error type with 7 ERR_VSDK_* codes

### Core Operations (8)

- `validate_manifest` -- Validate capsule manifest completeness and schema version
- `verify_capsule_signature` -- Verify capsule signature covers full payload
- `sign_capsule` -- Compute and set capsule signature
- `replay_capsule` -- Replay capsule and produce verdict
- `create_session` -- Create new verification session
- `record_session_step` -- Append replay result to session
- `seal_session` -- Seal session and compute final verdict
- `create_verifier_sdk` -- Create SDK facade instance

### Invariants

| ID | Description |
|----|-------------|
| INV-VSDK-CAPSULE-DETERMINISTIC | Same capsule always produces same verdict |
| INV-VSDK-NO-PRIVILEGE | No privileged internal access required |
| INV-VSDK-SCHEMA-VERSIONED | Every capsule carries schema version |
| INV-VSDK-SESSION-MONOTONIC | Session steps are append-only |
| INV-VSDK-SIGNATURE-BOUND | Signature covers manifest + payload + inputs |
| INV-CAPSULE-STABLE-SCHEMA | Capsule schema format is stable across versions |
| INV-CAPSULE-VERSIONED-API | Every API surface carries a version |
| INV-CAPSULE-NO-PRIVILEGED-ACCESS | Replay requires no privileged access |
| INV-CAPSULE-VERDICT-REPRODUCIBLE | Same capsule always yields same verdict |

### Event Codes

Internal: VSDK_001 through VSDK_007 covering capsule replay start,
completion (pass/fail), session creation, step recording, signature
verification, and manifest validation.

Public-facing: CAPSULE_CREATED, CAPSULE_SIGNED, CAPSULE_REPLAY_START,
CAPSULE_VERDICT_REPRODUCED, SDK_VERSION_CHECK.

### Error Codes

Internal: ERR_VSDK_CAPSULE_INVALID, ERR_VSDK_SIGNATURE_MISMATCH,
ERR_VSDK_SCHEMA_UNSUPPORTED, ERR_VSDK_REPLAY_DIVERGED,
ERR_VSDK_SESSION_SEALED, ERR_VSDK_MANIFEST_INCOMPLETE,
ERR_VSDK_EMPTY_PAYLOAD.

Public-facing: ERR_CAPSULE_SIGNATURE_INVALID, ERR_CAPSULE_SCHEMA_MISMATCH,
ERR_CAPSULE_REPLAY_DIVERGED, ERR_CAPSULE_VERDICT_MISMATCH,
ERR_SDK_VERSION_UNSUPPORTED, ERR_CAPSULE_ACCESS_DENIED.

## Verification

- Check script: `scripts/check_verifier_sdk_capsule.py` -- 70/70 checks PASS
- Self-test: 15/15 checks PASS
- Unit tests: `tests/test_check_verifier_sdk_capsule.py` -- 13/13 tests PASS
- Rust unit tests: 52 inline tests in implementation, 30 in SDK facade
- All types are Send + Sync, serde-serializable, BTreeMap for determinism

## Relationship to Existing Code

This module extends the verifier-economy SDK (`connector::verifier_sdk`, bd-3c2,
Section 10.12) with universally accessible capsule replay. Where bd-3c2 provides
claim/evidence/bundle verification primitives, bd-nbwo adds signed replay
capsules, verification sessions, and a stable external API surface.

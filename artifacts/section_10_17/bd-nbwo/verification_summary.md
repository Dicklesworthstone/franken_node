# bd-nbwo: Universal Verifier SDK and Replay Capsule Format

**Section:** 10.17 -- Radical Expansion Execution Track
**Verdict:** PASS

## Summary

This bead publishes a universal verifier SDK and replay capsule format that
enables external verifiers to replay signed capsules and reproduce claim
verdicts without privileged internal access. The capsule schema (`vsdk-v1.0`)
and verification APIs are stable and versioned.

The replacement-critical implementation surface is
`connector::universal_verifier_sdk`, which uses detached Ed25519 signatures
over a canonical signing payload. The standalone workspace crate
`sdk/verifier` remains structural-only and is documented as a companion
tooling surface rather than detached cryptographic authority.

The workspace replay-capsule companion contract now explicitly requires
sha256-shaped `expected_output_hash` values and exact `manifest.input_refs`
to replayed `inputs` binding, with duplicate declared refs rejected before
verdict evaluation.

## Deliverables

| Deliverable                | Path                                                               | Status |
|----------------------------|--------------------------------------------------------------------|--------|
| Replay capsule spec        | `docs/specs/replay_capsule_format.md`                              | PASS   |
| Bead contract              | `docs/specs/section_10_17/bd-nbwo_contract.md`                     | PASS   |
| Implementation (Rust)      | `crates/franken-node/src/connector/universal_verifier_sdk.rs`      | PASS   |
| SDK crate Cargo.toml       | `sdk/verifier/Cargo.toml`                                          | PASS   |
| SDK crate (lib.rs)         | `sdk/verifier/src/lib.rs`                                          | PASS   |
| SDK crate (capsule.rs)     | `sdk/verifier/src/capsule.rs`                                      | PASS   |
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

- `validate_manifest` -- Validate capsule manifest completeness, schema version, and sha256-shaped `expected_output_hash`
- `verify_capsule_signature` -- Verify the detached Ed25519 capsule signature
- `sign_capsule` -- Compute and set the detached Ed25519 capsule signature
- `replay_capsule` -- Replay capsule, reject duplicate or mismatched declared `input_refs`, and produce verdict
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

## Security Hardening (CrimsonCrane, 2026-03-10)

The SDK facade crate was hardened to eliminate three security bugs:

| Bug | Before | After |
|-----|--------|-------|
| Weak hash | XOR-based (collisions trivial) | SHA-256 with domain separator |
| Delimiter collision | Pipe-delimited field concatenation | Length-prefixed encoding |
| Timing attack | `!=` string comparison | `ct_eq` via `subtle::ConstantTimeEq` |

The SDK facade is now a proper Cargo crate (`frankenengine-verifier-sdk`) added to the
workspace, with `sha2`, `hex`, and `subtle` dependencies. 6 adversarial regression tests
cover: XOR collision resistance, delimiter collision, payload-input confusion, forged
same-length signatures, payload swap under reused signature, and cross-claim replay.

The public certification surface was also tightened so `bd-nbwo` fails closed
if docs/code/conformance drift away from these workspace manifest-binding
invariants:

- `expected_output_hash` must be a 64-character hex sha256 digest
- declared `manifest.input_refs` must be unique and exactly match replayed `inputs`

## Verification

- Check script: `scripts/check_verifier_sdk_capsule.py` -- 86/86 checks PASS
- Self-test: 15/15 checks PASS
- Unit tests: `tests/test_check_verifier_sdk_capsule.py` -- 20/20 tests PASS
- Rust unit tests: 54 inline tests in implementation, 49 across the SDK facade crate
- Clippy: 0 warnings with `-D warnings`
- All types are Send + Sync, serde-serializable, BTreeMap for determinism

## Relationship to Existing Code

This module extends the verifier-economy SDK (`connector::verifier_sdk`, bd-3c2,
Section 10.12) with universally accessible capsule replay. Where bd-3c2 provides
claim/evidence/bundle verification primitives, bd-nbwo adds detached-signature-
bound replay capsules, verification sessions, and a stable external API surface.

The workspace `sdk/verifier` crate stays in the repo as a structural-only
companion package for deterministic schema/replay tooling. It is explicitly not
the replacement-critical canonical verifier, which prevents the docs and
package metadata from overstating the trust posture of that helper surface.

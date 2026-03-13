# Replay Capsule Format Specification (bd-nbwo)

## Section

10.17 -- Radical Expansion Execution Track

## Overview

This specification defines the universal verifier SDK replay capsule format.
External verifiers replay detached-signature-bound capsules to reproduce claim
verdicts without requiring privileged internal access. The capsule schema and
verification APIs are stable and versioned.

The capsule format builds on the verifier-economy SDK (Section 10.12) and the
universal verifier SDK module (`connector::universal_verifier_sdk`), which is
the replacement-critical implementation surface. That connector module signs
and verifies capsules with detached Ed25519 signatures over a canonical signing
payload that binds manifest fields, metadata, payload bytes, and ordered
inputs.

The standalone workspace crate `sdk/verifier` is structural-only. It exposes
deterministic schema, replay, and structural signature digest helpers for
external tooling, but it is not the replacement-critical canonical verifier and
does not claim detached cryptographic verification authority.

## Capsule Format

A replay capsule is a self-contained, structurally bound unit consisting of:

1. **CapsuleManifest** -- metadata describing the capsule's contents, schema
   version, claim type, expected output hash, and creator identity.
2. **Payload** -- serialized data to replay.
3. **Inputs** -- deterministic-ordered (BTreeMap) input artifacts keyed by
   reference identifier.
4. **Signature** -- detached Ed25519 signature covering the manifest, payload,
   metadata, input refs, and inputs via the canonical signing payload.

### Schema Version

All capsules carry `schema_version = "vsdk-v1.0"`. The version is checked
during manifest validation; unsupported versions are rejected.

### Manifest Binding Requirements

`expected_output_hash` must be a 64-character hex sha256 digest.

Declared `input_refs` must be unique and exactly match the replayed `inputs`
keys.

### Detached Signature Coverage

The detached Ed25519 signature is computed over a canonical signing payload
that binds the following material:

- `capsule_id`
- `schema_version`
- `description`
- `claim_type`
- `expected_output_hash`
- `created_at`
- `creator_identity`
- `payload`
- ordered `input_refs`
- manifest metadata entries (including signer metadata)
- each input as `key=value` in `BTreeMap` order with length-prefixed encoding

## Replay Protocol

1. Validate the capsule manifest (schema version, required fields, and
   `expected_output_hash` shape).
2. Verify the capsule detached Ed25519 signature against the canonical signing
   payload using the signer public key embedded in manifest metadata.
3. Verify the declared `input_refs` are unique and exactly match the replayed
   `inputs` set.
4. Verify the payload is non-empty.
5. Compute the deterministic output hash from payload and inputs.
6. Compare the actual output hash against `expected_output_hash`.
7. Emit verdict: PASS if hashes match, FAIL otherwise.

## Verification Sessions

Multi-step verification workflows are modeled as `VerificationSession`:

- Sessions start empty and unsealed.
- Replay results are appended as `SessionStep` entries (append-only).
- Sessions can be sealed, computing a final verdict (PASS only if all steps
  passed, INCONCLUSIVE if no steps).
- Sealed sessions reject further step additions.

## Event Codes

| Code                       | Description                              |
|----------------------------|------------------------------------------|
| CAPSULE_CREATED            | A new replay capsule has been created    |
| CAPSULE_SIGNED             | A capsule has been signed                |
| CAPSULE_REPLAY_START       | Capsule replay has started               |
| CAPSULE_VERDICT_REPRODUCED | Capsule verdict has been reproduced      |
| SDK_VERSION_CHECK          | SDK version compatibility check          |
| VSDK_001                   | Capsule replay started (internal)        |
| VSDK_002                   | Capsule replay completed (PASS)          |
| VSDK_003                   | Capsule replay completed (FAIL)          |
| VSDK_004                   | Verification session created             |
| VSDK_005                   | Verification session step recorded       |
| VSDK_006                   | Capsule signature verified               |
| VSDK_007                   | Capsule manifest validated               |

## Error Codes

| Code                          | Description                                  |
|-------------------------------|----------------------------------------------|
| ERR_CAPSULE_SIGNATURE_INVALID | Capsule signature verification failed        |
| ERR_CAPSULE_SCHEMA_MISMATCH   | Capsule schema version is not supported      |
| ERR_CAPSULE_REPLAY_DIVERGED   | Replay output does not match expected hash   |
| ERR_CAPSULE_VERDICT_MISMATCH  | Reproduced verdict differs from original     |
| ERR_SDK_VERSION_UNSUPPORTED   | SDK version is not supported                 |
| ERR_CAPSULE_ACCESS_DENIED     | Privileged access attempted during replay    |
| ERR_VSDK_CAPSULE_INVALID      | Capsule structure is invalid                 |
| ERR_VSDK_SIGNATURE_MISMATCH   | Signature does not match payload             |
| ERR_VSDK_SCHEMA_UNSUPPORTED   | Schema version not supported                 |
| ERR_VSDK_REPLAY_DIVERGED      | Replay output diverges from expected         |
| ERR_VSDK_SESSION_SEALED       | Session is sealed, no more steps             |
| ERR_VSDK_MANIFEST_INCOMPLETE  | Manifest missing required fields             |
| ERR_VSDK_EMPTY_PAYLOAD        | Capsule payload is empty                     |

## Invariants

| ID                              | Description                                               |
|---------------------------------|-----------------------------------------------------------|
| INV-CAPSULE-STABLE-SCHEMA       | Capsule schema format is stable across SDK versions       |
| INV-CAPSULE-VERSIONED-API       | Every API surface carries a version identifier            |
| INV-CAPSULE-NO-PRIVILEGED-ACCESS| External replay requires no privileged internal access    |
| INV-CAPSULE-VERDICT-REPRODUCIBLE| Same capsule always produces the same verdict             |
| INV-VSDK-CAPSULE-DETERMINISTIC  | Replaying a capsule with same inputs yields same verdict  |
| INV-VSDK-NO-PRIVILEGE           | External verifiers never require privileged access        |
| INV-VSDK-SCHEMA-VERSIONED       | Every capsule and manifest carries a schema version       |
| INV-VSDK-SESSION-MONOTONIC      | Session steps are append-only                             |
| INV-VSDK-SIGNATURE-BOUND        | Detached Ed25519 signature binds full capsule payload     |

## Types

| Type                  | Purpose                                         |
|-----------------------|-------------------------------------------------|
| CapsuleVerdict        | Enum: Pass, Fail, Inconclusive                  |
| CapsuleManifest       | Describes capsule contents and expected outputs  |
| ReplayCapsule         | Signed, self-contained replay unit               |
| ReplayResult          | Outcome of replaying a capsule                   |
| SessionStep           | Single step in a verification session            |
| VerificationSession   | Stateful multi-step verification workflow         |
| VerifierSdk           | Top-level facade for external verifiers          |
| VsdkEvent             | Structured audit event                           |
| VsdkError             | Error type with ERR_VSDK_* codes                 |

## Core Operations

- `validate_manifest(manifest)` -- validate capsule manifest completeness
- `verify_capsule_signature(capsule)` -- verify the detached Ed25519 capsule signature
- `sign_capsule(capsule)` -- compute and set the detached Ed25519 capsule signature
- `replay_capsule(capsule, verifier_identity)` -- replay and produce verdict
- `create_session(id, verifier)` -- create new verification session
- `record_session_step(session, result)` -- append replay result to session
- `seal_session(session)` -- seal session and compute final verdict
- `create_verifier_sdk(verifier)` -- create SDK facade instance

## Dependencies

- bd-3c2: Verifier-economy SDK (Section 10.12)
- bd-2iyk: Information-flow lineage and exfiltration sentinel (Section 10.17)
- bd-1xbc: Deterministic time-travel runtime capture/replay (Section 10.17)

## Implementation

- Module: `crates/franken-node/src/connector/universal_verifier_sdk.rs`
- SDK crate: `sdk/verifier/` (`frankenengine-verifier-sdk`)
- Conformance test: `tests/conformance/verifier_sdk_capsule_replay.rs`

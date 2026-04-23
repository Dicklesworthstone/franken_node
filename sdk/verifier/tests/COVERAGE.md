# Verifier SDK Conformance Coverage Matrix

> **Status**: ✅ **100% conformance** for the spec-derived `conformance_harness.rs` matrix  
> **Last Updated**: 2026-04-23  
> **Test Suite**: `conformance_harness.rs`

## Coverage Summary

| Spec Section | MUST Clauses | SHOULD Clauses | MAY Clauses | Tested | Passing | Score |
|-------------|:-----------:|:--------------:|:-----------:|:------:|:-------:|-------|
| Schema Version | 5 | 0 | 0 | 5 | 5 | 100% |
| Event Codes | 5 | 0 | 0 | 5 | 5 | 100% |
| Error Codes | 6 | 0 | 0 | 6 | 6 | 100% |
| Invariants | 4 | 0 | 0 | 4 | 4 | 100% |
| Capsule Format | 8 | 2 | 0 | 10 | 10 | 100% |
| Bundle Format | 12 | 3 | 0 | 15 | 15 | 100% |
| SDK Interface | 11 | 1 | 0 | 12 | 12 | 100% |
| **TOTAL** | **51** | **6** | **0** | **57** | **57** | **100%** |

## Requirement Coverage Detail

### Schema Version Requirements (VSDK-SCHEMA-*)

| Test ID | Level | Description | Status |
|---------|-------|-------------|--------|
| VSDK-SCHEMA-1.1 | MUST | SDK_VERSION constant must be 'vsdk-v1.0' | ✅ PASS |
| VSDK-SCHEMA-1.2 | MUST | SDK_VERSION_MIN must match SDK_VERSION | ✅ PASS |
| VSDK-SCHEMA-1.3 | MUST | check_sdk_version must accept only vsdk-v1.0 | ✅ PASS |
| VSDK-SCHEMA-1.4 | MUST | check_sdk_version must reject all other versions | ✅ PASS |
| VSDK-SCHEMA-1.5 | MUST | REPLAY_BUNDLE_SCHEMA_VERSION must be vsdk-replay-bundle-v1.0 | ✅ PASS |

### Event Code Requirements (VSDK-EVENT-*)

| Test ID | Level | Description | Status |
|---------|-------|-------------|--------|
| VSDK-EVENT-2.1 | MUST | All event codes must be defined as constants | ✅ PASS |
| VSDK-EVENT-2.2 | MUST | Event codes must follow UPPERCASE naming convention | ✅ PASS |
| VSDK-EVENT-2.3 | MUST | SdkEvent must store event_code without modification | ✅ PASS |
| VSDK-EVENT-2.4 | MUST | SdkEvent must preserve arbitrary detail strings | ✅ PASS |
| VSDK-EVENT-2.5 | MUST | SdkEvent must support all defined event codes | ✅ PASS |

### Error Code Requirements (VSDK-ERROR-*)

| Test ID | Level | Description | Status |
|---------|-------|-------------|--------|
| VSDK-ERROR-3.1 | MUST | All error codes must start with ERR_ | ✅ PASS |
| VSDK-ERROR-3.2 | MUST | Error codes must be unique strings | ✅ PASS |
| VSDK-ERROR-3.3 | MUST | check_sdk_version must return ERR_SDK_VERSION_UNSUPPORTED | ✅ PASS |
| VSDK-ERROR-3.4 | MUST | VerifierSdkError must map to correct error codes | ✅ PASS |
| VSDK-ERROR-3.5 | MUST | CapsuleError must map to SDK error codes | ✅ PASS |
| VSDK-ERROR-3.6 | MUST | BundleError must map to SDK error codes | ✅ PASS |

### Invariant Requirements (VSDK-INVARIANT-*)

| Test ID | Level | Description | Status |
|---------|-------|-------------|--------|
| VSDK-INVARIANT-4.1 | MUST | INV-CAPSULE-STABLE-SCHEMA: capsule schema must be stable | ✅ PASS |
| VSDK-INVARIANT-4.2 | MUST | INV-CAPSULE-VERSIONED-API: all APIs must carry version | ✅ PASS |
| VSDK-INVARIANT-4.3 | MUST | INV-CAPSULE-NO-PRIVILEGED-ACCESS: replay self-contained | ✅ PASS |
| VSDK-INVARIANT-4.4 | MUST | INV-CAPSULE-VERDICT-REPRODUCIBLE: deterministic verdicts | ✅ PASS |

### Capsule Format Requirements (VSDK-CAPSULE-*)

| Test ID | Level | Description | Status |
|---------|-------|-------------|--------|
| VSDK-CAPSULE-5.1 | MUST | CapsuleManifest must include schema_version field | ✅ PASS |
| VSDK-CAPSULE-5.2 | MUST | CapsuleManifest must include all required fields | ✅ PASS |
| VSDK-CAPSULE-5.3 | MUST | ReplayCapsule must include manifest, payload, inputs, signature | ✅ PASS |
| VSDK-CAPSULE-5.4 | MUST | CapsuleVerdict must support Pass, Fail, Inconclusive | ✅ PASS |
| VSDK-CAPSULE-5.5 | MUST | CapsuleReplayResult must include expected/actual hashes | ✅ PASS |
| VSDK-CAPSULE-5.6 | MUST | CapsuleError must cover all error scenarios | ✅ PASS |
| VSDK-CAPSULE-5.7 | MUST | Capsule signature verification must be constant-time | ✅ PASS |
| VSDK-CAPSULE-5.8 | MUST | Capsule replay must be deterministic | ✅ PASS |
| VSDK-CAPSULE-5.9 | SHOULD | Capsule metadata should be preserved during replay | ✅ PASS |
| VSDK-CAPSULE-5.10 | SHOULD | Capsule inputs should validate against manifest | ✅ PASS |

### Bundle Format Requirements (VSDK-BUNDLE-*)

| Test ID | Level | Description | Status |
|---------|-------|-------------|--------|
| VSDK-BUNDLE-6.1 | MUST | ReplayBundle must include all required fields | ✅ PASS |
| VSDK-BUNDLE-6.2 | MUST | BundleHeader must specify hash algorithm and payload length | ✅ PASS |
| VSDK-BUNDLE-6.3 | MUST | TimelineEvent must include sequence_number and timestamp | ✅ PASS |
| VSDK-BUNDLE-6.4 | MUST | BundleChunk must specify index and total_chunks | ✅ PASS |
| VSDK-BUNDLE-6.5 | MUST | BundleArtifact must include digest and bytes_hex | ✅ PASS |
| VSDK-BUNDLE-6.6 | MUST | BundleSignature must specify algorithm and signature_hex | ✅ PASS |
| VSDK-BUNDLE-6.7 | MUST | Bundle serialization must be deterministic | ✅ PASS |
| VSDK-BUNDLE-6.8 | MUST | Bundle verification must validate integrity hash | ✅ PASS |
| VSDK-BUNDLE-6.9 | MUST | Bundle hash must use SHA-256 with domain separation | ✅ PASS |
| VSDK-BUNDLE-6.10 | MUST | Bundle Ed25519 signatures must be valid | ✅ PASS |
| VSDK-BUNDLE-6.11 | MUST | Bundle roundtrip (serialize->deserialize) preserves data | ✅ PASS |
| VSDK-BUNDLE-6.12 | MUST | Bundle tampering detection must be reliable | ✅ PASS |
| VSDK-BUNDLE-6.13 | SHOULD | Bundle compression should be supported | ✅ PASS |
| VSDK-BUNDLE-6.14 | SHOULD | Bundle chunking should handle large artifacts | ✅ PASS |
| VSDK-BUNDLE-6.15 | SHOULD | Bundle timeline should maintain causal ordering | ✅ PASS |

### SDK Interface Requirements (VSDK-INTERFACE-*)

| Test ID | Level | Description | Status |
|---------|-------|-------------|--------|
| VSDK-INTERFACE-7.1 | MUST | create_verifier_sdk must return configured VerifierSdk | ✅ PASS |
| VSDK-INTERFACE-7.2 | MUST | verify_claim must validate capsules and return result | ✅ PASS |
| VSDK-INTERFACE-7.3 | MUST | verify_migration_artifact must fail closed on structural-only replay bundles | ✅ PASS |
| VSDK-INTERFACE-7.4 | MUST | verify_trust_state must validate trust-anchor shape before failing closed on structural-only replay bundles | ✅ PASS |
| VSDK-INTERFACE-7.5 | MUST | ValidationWorkflow execution must preserve structural-bundle authentication guardrails | ✅ PASS |
| VSDK-INTERFACE-7.6 | MUST | VerificationSession must track steps and seal state | ✅ PASS |
| VSDK-INTERFACE-7.7 | MUST | create_session must reject malformed session ids | ✅ PASS |
| VSDK-INTERFACE-7.8 | MUST | TransparencyLogEntry must provide merkle proof chain | ✅ PASS |
| VSDK-INTERFACE-7.9 | MUST | VerificationResult must include confidence_score | ✅ PASS |
| VSDK-INTERFACE-7.10 | MUST | Result signatures must be verifiable and deterministic | ✅ PASS |
| VSDK-INTERFACE-7.11 | MUST | All interface methods must validate SDK version | ✅ PASS |
| VSDK-INTERFACE-7.12 | SHOULD | Interface should provide structured error details | ✅ PASS |

## Specification Source

The conformance tests validate against the **vsdk-v1.0 specification** as frozen in:

- `sdk/verifier/src/lib.rs` - Core SDK constants and types
- `sdk/verifier/src/bundle.rs` - Bundle format specification
- `sdk/verifier/src/capsule.rs` - Capsule format specification

## Test Architecture

### Pattern: Spec-Derived Tests (Pattern 4)

This conformance harness implements **Pattern 4: Spec-Derived Test Matrix** from the testing-conformance-harnesses skill. Each MUST/SHOULD clause from the vsdk-v1.0 specification has a corresponding test case with:

- **Unique Test ID**: VSDK-SECTION-N.M format for traceability
- **Requirement Level**: MUST (required) / SHOULD (recommended) / MAY (optional)
- **Clear Description**: What specific contract is being validated
- **Pass/Fail Verdict**: Binary outcome with detailed failure reasons

### Test Coverage Accounting

- **Total Requirements**: 57 (51 MUST + 6 SHOULD + 0 MAY)
- **Tested Requirements**: 57 (100% coverage)
- **Passing Tests**: 57 (100% conformance within the harness matrix)
- **Expected Failures**: 0 (for the clauses exercised by `conformance_harness.rs`)

### CI Integration

The conformance harness produces structured JSON output for automated reporting:

```json
{"id":"VSDK-SCHEMA-1.1","verdict":"PASS","level":"Must","section":"schema"}
```

## Known Divergences

**Harness Status**: No known divergences in the spec-derived `conformance_harness.rs` matrix.

**Auxiliary Fixture Drift**:
- `sdk/verifier/tests/fixtures/public_api/api_manifest.json` still documents an obsolete `VerifierSdk::new(...) -> Result<...>` constructor shape instead of the live facade constructor contract. This is tracked separately in `bd-3habd`.

This report summarizes the frozen clauses exercised by `conformance_harness.rs`. It does not claim that every auxiliary verifier fixture or contract artifact in `sdk/verifier/tests/` is already aligned. Intentional or discovered drift outside the harness should be called out here until the corresponding fixtures are updated.

## Maintenance

- **Test Updates**: Required only when vsdk specification changes (breaking)
- **Coverage Review**: Monthly audit to ensure new requirements are tested
- **Conformance Gate**: CI blocks merging if conformance score < 95%

---

**Conformance Score**: 🎯 **100%** (57/57 requirements validated)

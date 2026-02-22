# bd-3pds Contract: Integrate VEF evidence into verifier SDK replay capsules and external verification APIs

**Bead:** bd-3pds
**Section:** 10.18 (Verifiable Execution Fabric)
**Status:** Active
**Owner:** SilverMeadow

## Purpose

Bridge the VEF proof pipeline (Section 10.18) with the verifier SDK (Section 10.12/10.17) by embedding VEF compliance proofs into replay capsules and exposing a stable, versioned external verification API that external verifiers can call to submit and query VEF evidence.

## Configuration

| Field                   | Type     | Default | Description                                          |
|-------------------------|----------|---------|------------------------------------------------------|
| `format_version`        | String   | 1.0.0   | Current capsule embedding format version             |
| `min_format_version`    | String   | 1.0.0   | Minimum backward-compatible format version           |
| `schema_version`        | String   | vef-sdk-integration-v1 | Schema version for serialized data      |
| `max_query_limit`       | usize    | 1000    | Maximum records returned by a single query           |

## Event Codes

| Code    | Severity | Structured Log Event                      | Description                                    |
|---------|----------|-------------------------------------------|------------------------------------------------|
| VSI-001 | INFO     | `vsi.proof_embedded`                      | VEF proof embedded into replay capsule         |
| VSI-002 | INFO     | `vsi.evidence_submitted`                  | External verification evidence submitted       |
| VSI-003 | INFO     | `vsi.evidence_queried`                    | External verification query completed          |
| VSI-004 | INFO     | `vsi.version_negotiated`                  | Version negotiation completed                  |
| VSI-005 | INFO     | `vsi.embed_validated`                     | Capsule embedding validated                    |
| VSI-006 | INFO     | `vsi.evidence_exported`                   | Evidence bundle exported for external use      |

## Error Codes

| Code                          | Description                                       |
|-------------------------------|---------------------------------------------------|
| ERR-VSI-PROOF-REF-MISSING     | Proof reference is missing or empty               |
| ERR-VSI-CAPSULE-INVALID       | Capsule payload is empty or invalid               |
| ERR-VSI-VERSION-UNSUPPORTED   | Requested format version is not supported         |
| ERR-VSI-BINDING-MISMATCH      | Binding hash verification failed                  |
| ERR-VSI-SUBMISSION-REJECTED   | Evidence submission rejected (duplicate/malformed)|
| ERR-VSI-INTERNAL              | Internal serialization or hashing failure         |

## Invariants

- **INV-VSI-VERSIONED** -- Every capsule embedding and API response carries an explicit format version for forward/backward compatibility.
- **INV-VSI-BACKWARD-COMPAT** -- Version negotiation always selects the highest mutually supported version; unsupported versions produce classified errors.
- **INV-VSI-EMBED-COMPLETE** -- An embedded proof in a replay capsule is self-contained: it includes the proof reference, metadata, and a SHA-256 binding hash that ties the proof to the capsule payload.

## Types

### CapsuleEmbedding

| Field              | Type                    | Description                                      |
|--------------------|-------------------------|--------------------------------------------------|
| `format_version`   | String                  | Format version of this embedding                 |
| `proof_ref`        | String                  | Reference to the VEF compliance proof            |
| `embed_metadata`   | BTreeMap<String,String> | Metadata about the embedding (deterministic)     |
| `binding_hash`     | String                  | SHA-256 hash tying proof to capsule payload      |
| `trace_id`         | String                  | Trace correlation ID                             |
| `created_at_millis`| u64                     | Timestamp of embedding creation                  |

### EvidenceSubmission

| Field               | Type                    | Description                                     |
|---------------------|-------------------------|-------------------------------------------------|
| `submission_id`     | String                  | Unique submission identifier                    |
| `proof_ref`         | String                  | VEF proof reference                             |
| `format_version`    | String                  | Format version of submitted evidence            |
| `proof_payload`     | String                  | Serialized proof data                           |
| `metadata`          | BTreeMap<String,String> | Additional metadata                             |
| `trace_id`          | String                  | Trace correlation ID                            |
| `submitted_at_millis`| u64                    | Submission timestamp                            |

### SubmissionResponse

| Field              | Type           | Description                                      |
|--------------------|----------------|--------------------------------------------------|
| `submission_id`    | String         | Echo of submission identifier                    |
| `status`           | EvidenceStatus | Acceptance status                                |
| `format_version`   | String         | Server-side format version                       |
| `reason`           | String         | Reason for status (empty on success)             |
| `trace_id`         | String         | Trace correlation ID                             |

### NegotiationResult

| Field              | Type        | Description                                       |
|--------------------|-------------|---------------------------------------------------|
| `selected_version` | String      | Highest mutually supported version                |
| `client_versions`  | Vec<String> | Versions offered by client                        |
| `server_versions`  | Vec<String> | Versions supported by server                      |

### ExportedEvidenceBundle

| Field              | Type               | Description                                 |
|--------------------|--------------------|---------------------------------------------|
| `schema_version`   | String             | Schema version                              |
| `format_version`   | String             | Format version                              |
| `records`          | Vec<EvidenceRecord>| Exported evidence records                   |
| `exported_at_millis`| u64               | Export timestamp                             |
| `trace_id`         | String             | Trace correlation ID                        |

## Acceptance Criteria

1. `VefCapsuleEmbed` in `crates/franken-node/src/vef/sdk_integration.rs` embeds VEF proofs into replay capsules with deterministic binding hashes.
2. `ExternalVerificationEndpoint` accepts and stores VEF evidence submissions, validates versions, and supports filtered queries.
3. `VersionNegotiator` selects the highest mutually supported version and rejects unsupported versions.
4. `CapsuleEmbedding` struct carries format_version, proof_ref, embed_metadata, and binding_hash.
5. All operations emit structured events (VSI-001 through VSI-006).
6. All error conditions produce classified error codes.
7. Integration is versioned (INV-VSI-VERSIONED) and backward-compatible (INV-VSI-BACKWARD-COMPAT).
8. >= 25 unit tests covering all invariants and error paths.
9. Verification script `scripts/check_vef_sdk_integration.py` passes.
10. Evidence artifacts in `artifacts/section_10_18/bd-3pds/`.

## Dependencies

- Section 10.18 VEF proof pipeline (proof references).
- Section 10.12/10.17 Verifier SDK (replay capsule format).

## File Layout

```
docs/specs/section_10_18/bd-3pds_contract.md           (this file)
crates/franken-node/src/vef/sdk_integration.rs
scripts/check_vef_sdk_integration.py
tests/test_check_vef_sdk_integration.py
artifacts/section_10_18/bd-3pds/verification_evidence.json
artifacts/section_10_18/bd-3pds/verification_summary.md
```

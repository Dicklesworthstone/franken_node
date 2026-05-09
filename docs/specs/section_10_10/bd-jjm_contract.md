# bd-jjm Contract: Enforce Product-Level Adoption of Canonical Deterministic Serialization and Signature Preimage Rules

**Bead:** bd-jjm
**Section:** 10.10 (FCP-Inspired Hardening)
**Status:** Active
**Owner:** CrimsonCrane
**Priority:** P2

## Overview

Enhancement Map 9E.2 requires deterministic serialization and strict preimage
contracts for all signed trust artifacts. Every trust object that enters the
signing pipeline must pass through a single canonical serializer that enforces
field ordering, rejects floating-point values, and constructs domain-separated
signature preimages. This bead ensures that no signing route can bypass the
canonical serializer, and that round-trip serialization produces byte-identical
output for every trust object type.

## Dependencies

- **Upstream:** bd-3n2u (golden vectors from 10.13 for cross-implementation validation)
- **Upstream:** bd-1l5 (canonical trust object IDs with domain-separation tags)
- **Downstream:** bd-174 (policy checkpoint chain -- consumes canonical serialization)
- **Downstream:** bd-1hd (trust card signing -- consumes preimage construction)
- **Downstream:** bd-1jjq (section-wide verification gate)

## Data Model

### TrustObjectType (enum)

Six trust object types are subject to canonical serialization:

| Variant             | Domain Tag | Description                                    |
|---------------------|------------|------------------------------------------------|
| PolicyCheckpoint    | `0x5043`   | Policy state checkpoints (`PC`)                |
| DelegationToken     | `0x4454`   | Delegation tokens (`DT`)                       |
| RevocationAssertion | `0x5241`   | Revocation assertions (`RA`)                   |
| SessionTicket       | `0x5354`   | Session tickets (`ST`)                         |
| ZoneBoundaryClaim   | `0x5A42`   | Zone boundary claims (`ZB`)                    |
| OperatorReceipt     | `0x4F52`   | Operator receipts (`OR`)                       |

### CanonicalSchema (struct)

Defines the serialization schema for a single trust object type:

| Field        | Type           | Description                                       |
|--------------|----------------|---------------------------------------------------|
| object_type  | TrustObjectType| Which trust object this schema governs             |
| field_order  | Vec\<String\>  | Deterministic field ordering for serialization     |
| domain_tag   | [u8; 2]        | Two-byte domain-separation tag                     |
| version      | u8             | Schema version (monotonically increasing)          |

### CanonicalSerializer (struct)

Central serialization gateway. All signing routes must flow through this struct.

| Field    | Type                                       | Description                          |
|----------|--------------------------------------------|--------------------------------------|
| schemas  | HashMap\<TrustObjectType, CanonicalSchema\>| Registered schemas by object type    |

#### Methods

- **`register_schema(object_type: TrustObjectType, schema: CanonicalSchema)`**
  Registers a serialization schema for the given trust object type. Panics if
  a schema is already registered for that type (schemas are immutable once set).

- **`serialize(object_type: TrustObjectType, payload: &[u8]) -> Vec<u8>`**
  Performs deterministic serialization of the payload according to the registered
  schema's field ordering. Rejects payloads containing IEEE 754 floating-point
  values (returns `SerializerError::FloatingPointRejected`). The output bytes
  are canonical: re-serializing the same logical value always yields identical
  bytes.

- **`deserialize(object_type: TrustObjectType, bytes: &[u8]) -> Result<Vec<u8>, SerializerError>`**
  Deserializes canonical bytes back to payload form. Returns
  `SerializerError::SchemaNotFound` if no schema is registered for the type, or
  `SerializerError::NonCanonicalInput` if the bytes do not conform to the
  expected canonical layout.

- **`round_trip_canonical(object_type: TrustObjectType, payload: &[u8]) -> Result<(), SerializerError>`**
  Performs the full round-trip proof: serialize -> deserialize -> re-serialize,
  then asserts byte equality between the first and second serialization. Returns
  `SerializerError::RoundTripDivergence` if the two serialized forms differ.
  This is the canonical correctness proof for a given payload.

### SignaturePreimage (struct)

Structured preimage that is fed to the signing function. The domain tag prevents
cross-type signature confusion attacks.

| Field             | Type       | Description                                     |
|-------------------|------------|-------------------------------------------------|
| version           | u8         | Preimage format version (currently `1`)         |
| domain_tag        | [u8; 2]    | Two-byte domain-separation tag from schema      |
| canonical_payload | Vec\<u8\>  | Canonical-serialized payload bytes              |

#### Methods

- **`build(version: u8, domain_tag: [u8; 2], canonical_payload: Vec<u8>) -> Self`**
  Constructs a new SignaturePreimage. Validates that `version` is a known
  version and `domain_tag` is non-zero. Returns
  `SerializerError::PreimageConstructionFailed` on invalid inputs.

- **`to_bytes(&self) -> Vec<u8>`**
  Serializes the preimage to its final byte form for signing:
  `[version (1 byte)] || [domain_tag (2 bytes)] || [canonical_payload (N bytes)]`.
  This is the exact byte sequence that enters the signature function.

### SerializerEvent (struct)

Structured audit event emitted by the canonical serializer:

| Field        | Type            | Description                                    |
|--------------|-----------------|------------------------------------------------|
| event_code   | String          | One of the defined event codes                 |
| object_type  | TrustObjectType | Trust object type involved                     |
| trace_id     | String          | Correlation trace identifier                   |
| timestamp    | u64             | Unix timestamp of the event                    |
| payload_size | usize           | Size of the payload in bytes                   |
| success      | bool            | Whether the operation succeeded                |

### SerializerError (enum)

| Variant                    | Error Code                        | Description                                              |
|----------------------------|-----------------------------------|----------------------------------------------------------|
| NonCanonicalInput          | ERR_CAN_NON_CANONICAL             | Input bytes do not match canonical form                  |
| SchemaNotFound             | ERR_CAN_SCHEMA_NOT_FOUND          | No schema registered for the requested object type       |
| FloatingPointRejected      | ERR_CAN_FLOAT_REJECTED            | Payload contains IEEE 754 floating-point value           |
| PreimageConstructionFailed | ERR_CAN_PREIMAGE_FAILED           | Preimage construction failed (invalid version or tag)    |
| RoundTripDivergence        | ERR_CAN_ROUND_TRIP_DIVERGENCE     | Serialize-deserialize-reserialize produced different bytes|

## Invariants

| Invariant ID           | Statement                                                                  |
|------------------------|----------------------------------------------------------------------------|
| INV-CAN-DETERMINISTIC  | Same logical value produces identical bytes on every serialization call. Two calls to `serialize()` with the same `object_type` and `payload` must return byte-identical output regardless of call ordering, thread, or platform. |
| INV-CAN-NO-FLOAT       | No IEEE 754 floating-point values may appear in serialized trust artifacts. `serialize()` rejects any payload containing float or double fields with `FloatingPointRejected`. |
| INV-CAN-DOMAIN-TAG     | Every signature preimage includes a two-byte domain-separation tag. `SignaturePreimage::to_bytes()` always prefixes the canonical payload with `[version][domain_tag]`, and `build()` rejects zero-valued domain tags. |
| INV-CAN-NO-BYPASS      | All signing routes pass through `CanonicalSerializer`. No code path may construct a `SignaturePreimage` from non-canonical bytes. The `build()` method is the sole constructor and requires bytes produced by `serialize()`. |

## Event Codes

| Code                     | Severity | Description                                         |
|--------------------------|----------|-----------------------------------------------------|
| CAN_SERIALIZE            | INFO     | Canonical serialization completed successfully       |
| CAN_PREIMAGE_CONSTRUCT   | INFO     | Signature preimage constructed successfully          |
| CAN_REJECT               | WARN     | Serialization or preimage construction rejected      |

## Error Codes

| Code                            | Description                                                   |
|---------------------------------|---------------------------------------------------------------|
| ERR_CAN_NON_CANONICAL           | Input bytes do not match canonical form after re-serialization|
| ERR_CAN_SCHEMA_NOT_FOUND        | No schema registered for the requested TrustObjectType        |
| ERR_CAN_FLOAT_REJECTED          | Payload contains IEEE 754 floating-point value                |
| ERR_CAN_PREIMAGE_FAILED         | Preimage construction failed due to invalid version or tag    |
| ERR_CAN_ROUND_TRIP_DIVERGENCE   | Round-trip serialization produced divergent byte sequences    |

## Acceptance Criteria

1. **6 trust object types registered:** `CanonicalSerializer` has schemas
   registered for all 6 `TrustObjectType` variants (`PolicyCheckpoint`,
   `DelegationToken`, `RevocationAssertion`, `SessionTicket`,
   `ZoneBoundaryClaim`, `OperatorReceipt`) with correct domain tags and
   field orderings.

2. **Round-trip canonical passes for all types:** `round_trip_canonical()`
   succeeds for every registered `TrustObjectType` with representative
   payloads. The first and second serialization produce byte-identical output.

3. **Golden vector coverage from 10.13:** Canonical serialization output for
   each trust object type matches the golden vectors defined in bd-3n2u. At
   least one golden vector per type is validated.

4. **No bypass of CanonicalSerializer:** Static analysis or grep-based
   verification confirms that no code path constructs a `SignaturePreimage`
   from bytes not produced by `CanonicalSerializer::serialize()`. All signing
   call sites route through the canonical serializer.

5. **SignaturePreimage byte-identical across implementations:** The
   `to_bytes()` output for identical inputs matches across Rust and any
   reference implementation. Verified via golden vector comparison.

6. **Structured logging with trace IDs:** Every `serialize()`,
   `round_trip_canonical()`, and `SignaturePreimage::build()` call emits a
   `SerializerEvent` with a non-empty `trace_id` field. Events are emitted on
   both success and failure paths.

7. **No floating-point in serialized artifacts:** `serialize()` returns
   `SerializerError::FloatingPointRejected` when a payload containing a
   floating-point value is submitted. Unit tests verify rejection for f32, f64,
   and NaN-bearing payloads.

8. **Evidence artifact passes schema:** The verification evidence JSON at
   `artifacts/section_10_10/bd-jjm/verification_evidence.json` conforms to the
   project evidence schema and contains passing results for all acceptance
   criteria.

## Verification

- Script: `scripts/check_canonical_serialization.py --json`
- Tests: `tests/test_check_canonical_serialization.py`
- Evidence: `artifacts/section_10_10/bd-jjm/verification_evidence.json`
- Summary: `artifacts/section_10_10/bd-jjm/verification_summary.md`

The verification script must not satisfy behavior checks with a Python mirror
of the serializer. Observable behavior evidence comes from registered Rust test
targets that exercise the production `CanonicalSerializer`,
`canonical_serialization_round_trips()`, canonical preimage construction,
decode/re-encode behavior, and golden preimage bytes. If those Rust targets,
their source files, or the policy-checkpoint preimage golden are unavailable,
the script reports a failing production-evidence check.

## Artifacts

| Artifact                                                             | Purpose                        |
|----------------------------------------------------------------------|--------------------------------|
| `docs/specs/section_10_10/bd-jjm_contract.md`                       | This specification document    |
| `crates/franken-node/src/connector/canonical_serializer.rs`          | Rust implementation            |
| `scripts/check_canonical_serialization.py`                           | Verification script (--json)   |
| `tests/test_check_canonical_serialization.py`                        | Unit tests for verifier        |
| `artifacts/section_10_10/bd-jjm/verification_evidence.json`         | Machine-readable evidence      |
| `artifacts/section_10_10/bd-jjm/verification_summary.md`            | Human-readable summary         |

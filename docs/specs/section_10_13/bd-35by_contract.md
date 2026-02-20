# bd-35by — Mandatory Interop Suites

## Overview

Builds mandatory interoperability test suites for the five core contract
classes: serialization, object-id, signature, revocation, and source-diversity.
Each suite validates that independent implementations produce compatible
outputs.  Failures include minimal reproducer fixtures.

## Interop Classes

| Class | Purpose |
|-------|---------|
| Serialization | Round-trip encode/decode produces identical output |
| Object-ID | IDs are deterministic given same inputs |
| Signature | Signatures verify across implementations |
| Revocation | Revocation status is agreed upon |
| Source-Diversity | Multi-source attestation meets threshold |

## Invariants

- **INV-IOP-SERIALIZATION** — Round-trip serialization produces identical
  byte output across implementations; mismatches produce a reproducer fixture.
- **INV-IOP-OBJECT-ID** — Object IDs are deterministic: same inputs always
  produce the same ID across implementations.
- **INV-IOP-SIGNATURE** — Signatures produced by one implementation verify
  correctly in another; cross-implementation verification never silently fails.
- **INV-IOP-REVOCATION** — Revocation status checks agree across implementations;
  a revoked credential is never treated as valid.
- **INV-IOP-SOURCE-DIVERSITY** — Multi-source attestation requires a configurable
  minimum number of independent sources; under-attested claims are rejected.

## Types

- `InteropClass` — Serialization / ObjectId / Signature / Revocation / SourceDiversity
- `InteropTestCase` — class, input, expected output, implementation
- `InteropResult` — class, passed, details, reproducer
- `InteropSuite` — runs all test cases for all classes
- `InteropError` — error codes for contract violations

## Error Codes

| Code | Meaning |
|------|---------|
| `IOP_SERIALIZATION_MISMATCH` | Round-trip output differs |
| `IOP_OBJECT_ID_MISMATCH` | Deterministic ID differs |
| `IOP_SIGNATURE_INVALID` | Cross-impl signature verification failed |
| `IOP_REVOCATION_DISAGREEMENT` | Revocation status differs |
| `IOP_SOURCE_DIVERSITY_INSUFFICIENT` | Not enough independent sources |

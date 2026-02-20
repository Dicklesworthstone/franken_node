# bd-3n2u — Formal Schema Spec & Golden Vectors

## Overview

Publishes normative schema specification files and golden test vectors for
serialization, signatures, and control-channel frames.  Schemas and vectors
are versioned.  A verification runner validates implementations against the
full vector suite.  Vector changes require explicit changelog entries.

## Schema Categories

| Category | Description |
|----------|-------------|
| Serialization | Object encoding/decoding format |
| Signature | Signing and verification format |
| Control Frame | Control-channel message structure |

## Invariants

- **INV-GSV-SCHEMA** — Normative schema files exist for all three categories
  (serialization, signature, control-frame) with version metadata.
- **INV-GSV-VECTORS** — Golden test vectors exist for each schema category;
  each vector includes input, expected output, and category.
- **INV-GSV-VERIFIED** — A verification runner validates all vectors against
  the implementation; any mismatch is reported with the failing vector.
- **INV-GSV-CHANGELOG** — Schema and vector files include a changelog; adding
  or modifying vectors requires a changelog entry.

## Types

- `SchemaCategory` — Serialization / Signature / ControlFrame
- `SchemaSpec` — category, version, content_hash, changelog entries
- `GoldenVector` — category, vector_id, input, expected_output, description
- `VectorVerificationResult` — vector_id, passed, details
- `SchemaError` — error codes

## Error Codes

| Code | Meaning |
|------|---------|
| `GSV_MISSING_SCHEMA` | Required schema file not found |
| `GSV_MISSING_VECTOR` | Category has no golden vectors |
| `GSV_VECTOR_MISMATCH` | Vector output does not match expected |
| `GSV_NO_CHANGELOG` | Vector change without changelog entry |
| `GSV_INVALID_VERSION` | Schema version is missing or invalid |

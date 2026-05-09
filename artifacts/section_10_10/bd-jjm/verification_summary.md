# bd-jjm: Canonical Deterministic Serialization and Signature Preimage Rules

**Section:** 10.10 | **Verdict:** PASS | **Date:** 2026-02-21

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Python verification checks | 109 | 109 |
| Rust unit test inventory | 135 | 135 |
| Production Rust evidence checks | 25 | 25 |

## Implementation

**File:** `crates/franken-node/src/connector/canonical_serializer.rs`

### Core Types (6 structs/enums)
- `TrustObjectType` — PolicyCheckpoint, DelegationToken, RevocationAssertion, SessionTicket, ZoneBoundaryClaim, OperatorReceipt
- `CanonicalSerializer` — stateful serializer with schema registry
- `SignaturePreimage` — domain-separated preimage with version, tag, payload
- `CanonicalSchema` — per-type field ordering, domain tag, version, no-float flag
- `SerializerEvent` — structured audit events with trace_id
- `SerializerError` — typed errors with stable codes

### Key API Methods
- `serialize(type, payload)` — deterministic length-prefixed encoding
- `deserialize(type, bytes)` — decode with validation
- `round_trip_canonical(type, payload)` — byte-stability proof
- `build_preimage(type, payload)` — domain-separated signature preimage
- `with_all_schemas()` — pre-loaded with all 6 canonical schemas
- `canonical_serialization_round_trips()` — batch API over production serializer records

### Event Codes (3)
| Code | Description |
|------|-------------|
| CAN_SERIALIZE | Successful canonical serialization |
| CAN_PREIMAGE_CONSTRUCT | Signature preimage constructed |
| CAN_REJECT | Non-canonical input rejected |

### Error Codes (5)
- ERR_CAN_NON_CANONICAL, ERR_CAN_SCHEMA_NOT_FOUND, ERR_CAN_FLOAT_REJECTED
- ERR_CAN_PREIMAGE_FAILED, ERR_CAN_ROUND_TRIP_DIVERGENCE

### Invariants (4)
- **INV-CAN-DETERMINISTIC**: Same logical value produces identical bytes
- **INV-CAN-NO-FLOAT**: No floating-point in serialized trust artifacts
- **INV-CAN-DOMAIN-TAG**: Every preimage includes domain-separation tag
- **INV-CAN-NO-BYPASS**: All signing routes through CanonicalSerializer

## Policy

**File:** `docs/policy/canonical_deterministic_serialization.md` (POL-CAN-001)

Covers serialization rules, preimage construction format, float rejection,
domain separation, and compliance requirements.

## Verification Commands

The Python gate no longer uses a Python serializer simulation as behavior
evidence. It requires registered Rust test targets that exercise
`CanonicalSerializer`, `canonical_serialization_round_trips()`,
`round_trip_canonical()`, `build_preimage()`, `deserialize()`, and the reviewed
policy-checkpoint preimage golden.

```bash
python3 scripts/check_canonical_serialization.py --json    # 109/109 PASS
python3 -m unittest tests.test_check_canonical_serialization  # 23/23 PASS
rch exec -- cargo test -p frankenengine-node --test canonical_serializer_real_inputs --test canonical_serializer_conformance --test canonical_serializer_metamorphic
```

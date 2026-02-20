# bd-3cm3: Schema-Gated Quarantine Promotion — Verification Summary

## Verdict: PASS (6/6 checks)

## Implementation

`crates/franken-node/src/connector/quarantine_promotion.rs`

- `evaluate_promotion()`: checks auth, schema version, reachability, pin in order
- Fail-closed: any rejection → object stays quarantined, no receipt emitted
- `ProvenanceReceipt`: full audit trail with validator_id, trace_id, reason, schema_version
- `evaluate_batch()`: deterministic batch processing in order

## Invariants Verified

| Invariant | Status | Evidence |
|-----------|--------|----------|
| INV-QPR-SCHEMA-GATED | PASS | Wrong schema version rejected (16 unit tests, integration test) |
| INV-QPR-AUTHENTICATED | PASS | Unauthenticated requests rejected |
| INV-QPR-RECEIPT | PASS | Every success emits ProvenanceReceipt with full provenance |
| INV-QPR-FAIL-CLOSED | PASS | Any single failure blocks promotion; multiple failures all recorded |

## Error Codes

All 5 error codes present: QPR_SCHEMA_FAILED, QPR_NOT_AUTHENTICATED, QPR_NOT_REACHABLE, QPR_NOT_PINNED, QPR_INVALID_RULE.

## Test Results

- 16 Rust unit tests passed
- 4 integration tests (1 per invariant)
- 15 Python verification tests passed
- Promotion receipts fixture with 2 successes and 3 rejections

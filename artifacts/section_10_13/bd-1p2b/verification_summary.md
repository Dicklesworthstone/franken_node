# bd-1p2b: Control-Plane Retention Policy — Verification Summary

## Verdict: PASS (6/6 checks)

## Implementation

`crates/franken-node/src/connector/retention_policy.rs`

- `RetentionClass`: Required (never dropped) vs Ephemeral (TTL-based expiry)
- `RetentionRegistry`: per-message-type policy lookup; rejects unclassified types
- `RetentionStore`: storage with enforcement — required never dropped, ephemeral cleaned on TTL/pressure
- `cleanup_ephemeral()`: TTL-based cleanup; also triggered on storage pressure during store()
- All store/drop actions produce `RetentionDecision` audit records

## Invariants Verified

| Invariant | Status | Evidence |
|-----------|--------|----------|
| INV-CPR-CLASSIFIED | PASS | Unclassified message types rejected with CPR_UNCLASSIFIED |
| INV-CPR-REQUIRED-DURABLE | PASS | Required objects cannot be dropped; survive ephemeral cleanup |
| INV-CPR-EPHEMERAL-POLICY | PASS | Ephemeral objects dropped only when TTL expires or storage pressure |
| INV-CPR-AUDITABLE | PASS | Every store/drop emits RetentionDecision with type, class, reason |

## Test Results

- 18 Rust unit tests passed
- 4 integration tests (1 per invariant)
- 13 Python verification tests passed
- Policy matrix fixture with 10 message types (6 required, 4 ephemeral)

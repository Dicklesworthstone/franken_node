# bd-390 Contract: Anti-Entropy Reconciliation

**Bead:** bd-390
**Section:** 10.11 (FrankenSQLite-Inspired Runtime Systems)
**Status:** Active

## Purpose

Implement O(delta) anti-entropy reconciliation for distributed product trust
state.  Two nodes exchange Merkle-Mountain-Range digests and reconcile only
the differing records, producing proof-carrying recovery artifacts for each
reconciled entry.  Epoch and proof violations are enforced fail-closed for the
individual record: the record is rejected, not applied, counted in
`records_rejected`, and surfaced through `FN-AE-004` with the matching
structured rejection reason.

## Algorithm

1. Each node computes an MMR digest over its trust-state records.
2. Nodes exchange digests and diff via MMR prefix comparison → O(delta).
3. Missing/divergent records are bundled with MMR inclusion proofs.
4. Same-ID conflicts are resolved deterministically by higher `epoch`, then
   later `recorded_at_ms`, then lexicographically greater `origin_node_id`;
   only exact precedence ties with different digests are treated as forks.
5. Records are applied through a two-phase obligation channel (atomic).
6. Epoch-scoped validity: reject records from future epochs in-band without
   applying them.
7. Fork detection: divergent histories trigger halt-and-alert.

## Data Structures

### `ReconciliationConfig`

| Field                 | Type   | Default | Description                          |
|-----------------------|--------|---------|--------------------------------------|
| max_delta_batch       | usize  | 1000    | Max records per reconciliation batch |
| epoch_tolerance       | u64    | 0       | Max epoch ahead to accept (0=strict) |
| proof_required        | bool   | true    | Require MMR inclusion proofs         |
| cancellation_enabled  | bool   | true    | Support cancellation mid-reconcile   |
| max_retry_attempts    | usize  | 3       | Retries for transient failures       |

### `TrustRecord`

| Field       | Type     | Description                         |
|-------------|----------|-------------------------------------|
| id              | String      | Unique record identifier                 |
| epoch           | u64         | Epoch in which record was created        |
| recorded_at_ms  | u64         | Monotonic origin timestamp               |
| origin_node_id  | String      | Deterministic final tie-breaker          |
| payload         | Vec<u8>     | Record payload bytes                     |
| mmr_pos         | u64         | MMR leaf position                        |
| mmr_proof       | Vec<[u8;32]>| MMR inclusion proof hashes               |

### `ReconciliationResult`

| Field             | Type   | Description                         |
|-------------------|--------|-------------------------------------|
| delta_size        | usize  | Number of differing records         |
| records_accepted  | usize  | Successfully reconciled             |
| records_rejected  | usize  | Rejected per-record (epoch/proof/capacity) |
| elapsed_ms        | u64    | Wall-clock time in milliseconds     |
| fork_detected     | bool   | Whether fork was detected           |
| cancelled         | bool   | Whether reconciliation was cancelled|

## Event Codes

| Code      | Severity | Description                                    |
|-----------|----------|------------------------------------------------|
| FN-AE-001 | INFO    | Reconciliation cycle started                   |
| FN-AE-002 | INFO    | Delta computed between local and remote state  |
| FN-AE-003 | INFO    | Record accepted and applied                    |
| FN-AE-004 | WARN    | Record rejected (epoch/proof/capacity violation) |
| FN-AE-005 | INFO    | Reconciliation cycle completed                 |
| FN-AE-006 | ERROR   | Fork detected, reconciliation halted           |
| FN-AE-007 | WARN    | Reconciliation cancelled mid-cycle             |
| FN-AE-008 | INFO    | Replay of already-reconciled record (idempotent)|

## Invariants

- **INV-AE-DELTA** — Reconciliation processes only O(delta) records, not
  full state.
- **INV-AE-ATOMIC** — Partial reconciliation failures leave local state
  unchanged (two-phase rollback).
- **INV-AE-EPOCH** — Records from future epochs (epoch > local_current +
  tolerance) are rejected fail-closed, emit `FN-AE-004` with
  `ERR_AE_EPOCH_VIOLATION`, increment `records_rejected`, and are not applied.
- **INV-AE-PROOF** — Every accepted reconciled record includes a verifiable MMR
  inclusion proof. Missing or invalid proofs emit `FN-AE-004` with
  `ERR_AE_PROOF_INVALID`, increment `records_rejected`, and are not applied.

## Error Codes

| Code                     | Description                              |
|--------------------------|------------------------------------------|
| ERR_AE_INVALID_CONFIG    | Configuration parameter out of range     |
| ERR_AE_EPOCH_VIOLATION   | Record epoch exceeds local current epoch plus tolerance |
| ERR_AE_PROOF_INVALID     | MMR inclusion proof verification failed  |
| ERR_AE_FORK_DETECTED     | Divergent histories detected             |
| ERR_AE_CANCELLED         | Reconciliation cancelled mid-cycle       |
| ERR_AE_BATCH_EXCEEDED    | Delta exceeds max_delta_batch            |

## Acceptance Criteria

1. O(delta) reconciliation: two states with N records, K differing → O(K) work.
2. Every accepted reconciled record includes verifiable MMR inclusion proof.
3. Future-epoch records are rejected in-band with `FN-AE-004`,
   `ERR_AE_EPOCH_VIOLATION`, and `records_rejected += 1`.
4. Missing or invalid proof records are rejected in-band with `FN-AE-004`,
   `ERR_AE_PROOF_INVALID`, and `records_rejected += 1`.
5. Crash/cancellation mid-reconciliation leaves state unchanged.
6. Structured log events FN-AE-001 through FN-AE-008.
7. Fork detection triggers halt-and-alert.
8. Replay of already-reconciled records is idempotent.
9. >= 30 unit tests.
10. Verification script passes all checks.

## Dependencies

- 10.14 MMR primitives (epoch, proofs)
- bd-1jpo (section 10.11 gate) — downstream

## File Layout

```
docs/specs/section_10_11/bd-390_contract.md (this file)
crates/franken-node/src/runtime/anti_entropy.rs
scripts/check_anti_entropy_reconciliation.py
tests/test_check_anti_entropy_reconciliation.py
artifacts/section_10_11/bd-390/verification_evidence.json
artifacts/section_10_11/bd-390/verification_summary.md
```

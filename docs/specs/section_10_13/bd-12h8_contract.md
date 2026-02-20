# bd-12h8: Persist Required Artifacts with Deterministic Replay

## Purpose

Persist required control-plane artifacts (invoke, response, receipt, approval, revocation, audit) with deterministic replay hooks. Every persisted artifact is replayable from its stored state.

## Invariants

- **INV-PRA-COMPLETE**: All 6 required artifact types (invoke, response, receipt, approval, revocation, audit) are persistable.
- **INV-PRA-DURABLE**: Persisted artifacts survive cleanup; no silent data loss.
- **INV-PRA-REPLAY**: Every persisted artifact can be replayed deterministically from stored state.
- **INV-PRA-ORDERED**: Artifacts are retrievable in insertion order per sequence for replay correctness.

## Types

### ArtifactType

Enum: Invoke, Response, Receipt, Approval, Revocation, Audit.

### PersistedArtifact

Stored artifact: artifact_id, artifact_type, sequence_number, payload_hash, stored_at, trace_id.

### ReplayHook

Replay descriptor: artifact_id, artifact_type, sequence_number, payload_hash, replay_order.

### PersistenceResult

Outcome: artifact_id, persisted (bool), sequence_number, trace_id.

## Error Codes

- `PRA_UNKNOWN_TYPE` — artifact type not recognized
- `PRA_DUPLICATE` — artifact already persisted
- `PRA_SEQUENCE_GAP` — sequence number gap detected
- `PRA_REPLAY_MISMATCH` — replay hash does not match stored hash
- `PRA_INVALID_ARTIFACT` — artifact validation failed

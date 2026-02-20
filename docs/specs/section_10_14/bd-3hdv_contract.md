# bd-3hdv: Monotonic Control Epoch in Canonical Manifest State

## Purpose

Define the foundational time-fencing primitive for the 9J track: a strictly
monotonic, durable, 64-bit control epoch counter embedded in the canonical
manifest state. Every trust decision, key derivation, validity window, and
transition barrier references this epoch to distinguish "before" from "after"
a security-relevant configuration change.

## Dependencies

- **Upstream:** none (root of epoch dependency chain)

## Types

### `ControlEpoch`

A `Copy + Ord + Hash + Eq + Serialize + Deserialize` wrapper around `u64`.
Genesis value is 0; the first meaningful epoch is 1. Supports `From<u64>` and
`Into<u64>` conversions. Serde serialization is transparent (serializes as bare `u64`).

### `EpochTransition`

A signed event recording an epoch change:
- `old_epoch: ControlEpoch`
- `new_epoch: ControlEpoch`
- `timestamp: u64`
- `manifest_hash: String` (binding to manifest state)
- `event_mac: String` (keyed MAC for integrity verification)
- `trace_id: String`

### `EpochError`

Three stable error codes:
- `EPOCH_REGRESSION` — attempted to set epoch to value <= current
- `EPOCH_OVERFLOW` — epoch at u64::MAX, cannot advance
- `EPOCH_INVALID_MANIFEST` — empty or invalid manifest hash

### `EpochStore`

Durable epoch store managing the canonical epoch counter.

## Operations

### `epoch_read() -> ControlEpoch`

O(1) non-mutating read of the current epoch.

### `epoch_advance(manifest_hash, timestamp, trace_id) -> Result<EpochTransition, EpochError>`

Atomically increments epoch by exactly 1. Produces a signed `EpochTransition`
event. Commits the new epoch durably.

### `epoch_set(value, manifest_hash, timestamp, trace_id) -> Result<EpochTransition, EpochError>`

Sets epoch to a specific value. Rejected if value <= current (regression).

### `recover(committed_epoch) -> EpochStore`

Create a store from durable state after crash recovery.

## Invariants

| ID | Description |
|----|-------------|
| INV-EPOCH-MONOTONIC | Epoch values only increase; regressions are rejected |
| INV-EPOCH-DURABLE | Committed epoch survives crash recovery |
| INV-EPOCH-SIGNED-EVENT | Every epoch change produces a signed transition event |
| INV-EPOCH-NO-GAP | epoch_advance increments by exactly 1 |

## Persistence Model

- In-memory: `EpochStore.current` and `EpochStore.committed`
- On advance: both values updated atomically (simulates write-then-fsync)
- Crash recovery: only `committed` survives; in-memory history lost
- Production path: WAL-mode SQLite with fsync after each epoch write

## Event Schema

```json
{
  "event_code": "EPOCH_ADVANCED",
  "old_epoch": 41,
  "new_epoch": 42,
  "timestamp": 1708444800000,
  "manifest_hash": "sha256:abc123...",
  "event_mac": "mac:0123456789abcdef",
  "trace_id": "trace-0042"
}
```

## Performance Targets

- `epoch_read`: O(1), < 1 microsecond
- `epoch_advance`: O(1) amortized (excluding I/O), < 10 microseconds

## Edge Cases

- Genesis epoch (0) is valid starting state
- u64::MAX epoch cannot advance (overflow error)
- Empty manifest hash is rejected
- Same-value regression is rejected
- Crash at any point: recovery sees old or new epoch, never a third value

## Artifacts

- Implementation: `crates/franken-node/src/control_plane/control_epoch.rs`
- Spec: `docs/specs/section_10_14/bd-3hdv_contract.md`
- Evidence: `artifacts/section_10_14/bd-3hdv/verification_evidence.json`
- Summary: `artifacts/section_10_14/bd-3hdv/verification_summary.md`

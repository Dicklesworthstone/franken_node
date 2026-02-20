# bd-3hdv: Verification Summary

## Monotonic Control Epoch in Canonical Manifest State

### Implementation

- **File:** `crates/franken-node/src/control_plane/control_epoch.rs`
- **Module wired:** `control_plane/mod.rs` includes `pub mod control_epoch`
- **Types:** `ControlEpoch` (Copy + Ord + Hash + Serialize + Deserialize), `EpochTransition`, `EpochStore`, `EpochError`
- **Operations:** `epoch_advance`, `epoch_read`, `epoch_set`, `recover`, `committed_epoch`
- **Error codes:** `EPOCH_REGRESSION`, `EPOCH_OVERFLOW`, `EPOCH_INVALID_MANIFEST`
- **Event codes:** `EPOCH_ADVANCED`, `EPOCH_REGRESSION_REJECTED`, `EPOCH_READ`, `EPOCH_RECOVERED`

### Invariants

| ID | Status |
|----|--------|
| INV-EPOCH-MONOTONIC | Verified (1000-advance test, regression rejection) |
| INV-EPOCH-DURABLE | Verified (crash recovery simulation) |
| INV-EPOCH-SIGNED-EVENT | Verified (MAC computation + tamper detection) |
| INV-EPOCH-NO-GAP | Verified (sequential advance + gap rejection) |

### Verification Results

| Check | Result |
|-------|--------|
| Python verification (57 checks) | PASS |
| Python unit tests (34 tests) | PASS |
| Rust unit tests (30 tests) | PASS |
| `cargo check --all-targets` | PASS (14 pre-existing warnings) |

### Notes

- `cargo fmt --check` and `cargo clippy` have pre-existing failures outside this bead's scope
- Serde `Serialize + Deserialize` derives added to `ControlEpoch` and `EpochTransition` for serialization ergonomics
- `serde(transparent)` on `ControlEpoch` ensures it serializes as bare `u64`

### Downstream Unblocks

- bd-2xv8 (fail-closed validity window)
- bd-3cs3 (epoch-scoped key derivation)
- bd-2wsm (epoch transition barrier)
- bd-25nl (root-auth bootstrap)
- bd-22yy (DPOR exploration)
- bd-181w (10.15 epoch windows)
- bd-2gr (10.11 epoch integration)

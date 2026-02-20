# Validity Window Rules (bd-2xv8)

## Purpose

Enforce fail-closed epoch admission for artifacts so no artifact from a future
epoch can be processed before the control plane reaches that epoch.

This contract depends on monotonic control epochs (`bd-3hdv`) and protects
downstream epoch-scoped systems.

## Policy

`ValidityWindowPolicy` defines:

- `current_epoch: ControlEpoch`
- `max_lookback: u64`

Accepted artifact epochs are inclusive in:

`[current_epoch - max_lookback, current_epoch]`

### Rejection semantics

1. `artifact_epoch > current_epoch` -> reject with `FutureEpoch`
2. `artifact_epoch < current_epoch - max_lookback` -> reject with `ExpiredEpoch`
3. Otherwise accept

The check is deterministic and fail-closed.

## API

`check_artifact_epoch(artifact_id, artifact_epoch, policy, trace_id) -> Result<(), EpochRejection>`

`EpochRejection` includes:

- `artifact_id`
- `artifact_epoch`
- `current_epoch`
- `rejection_reason` (`FutureEpoch` or `ExpiredEpoch`)
- `trace_id`

Stable rejection codes:

- `EPOCH_REJECT_FUTURE`
- `EPOCH_REJECT_EXPIRED`

Structured event codes:

- `EPOCH_ARTIFACT_ACCEPTED`
- `EPOCH_ARTIFACT_REJECTED`

Event payload schema:

- `event_code`
- `artifact_id`
- `artifact_epoch`
- `current_epoch`
- `rejection_reason` (`null` on accept)
- `trace_id`

Implemented by `EpochArtifactEvent` in
`crates/franken-node/src/control_plane/control_epoch.rs`.

## Runtime reconfiguration

Policy supports hot-reload via:

- `set_current_epoch(...)`
- `set_max_lookback(...)`

Default lookback is `1` (`ValidityWindowPolicy::default_for(...)`).

## Ingestion enforcement

`ArtifactStore::persist(...)` in
`crates/franken-node/src/connector/artifact_persistence.rs` runs
`check_artifact_epoch(...)` before any persistence-side mutation. Rejections are
returned as `PersistenceError::EpochRejected` and can be translated to
`EPOCH_ARTIFACT_REJECTED` telemetry using `EpochRejection::to_rejected_event()`.

## Boundary behavior

- `artifact_epoch == current_epoch` -> accepted
- `artifact_epoch == current_epoch - max_lookback` -> accepted
- `current_epoch - max_lookback` underflows -> saturates to epoch `0`

## Test obligations

Covered by:

- Unit tests in `crates/franken-node/src/control_plane/control_epoch.rs`
- Security conformance file `tests/security/future_epoch_rejection.rs`

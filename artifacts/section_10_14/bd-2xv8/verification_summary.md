# bd-2xv8 Verification Summary

## Outcome

Implemented fail-closed epoch validity-window enforcement and wired it into artifact ingestion so persistence cannot proceed without passing epoch checks.

## What Was Delivered

- `ValidityWindowPolicy` + `check_artifact_epoch(...)` reject future and expired epochs deterministically.
- Typed `EpochRejection` with stable rejection codes:
  - `EPOCH_REJECT_FUTURE`
  - `EPOCH_REJECT_EXPIRED`
- Structured telemetry payload `EpochArtifactEvent` with event codes:
  - `EPOCH_ARTIFACT_ACCEPTED`
  - `EPOCH_ARTIFACT_REJECTED`
- Artifact ingestion enforcement:
  - `ArtifactStore::persist(...)` now requires `artifact_epoch` and executes epoch-window validation before mutation.
- Added/updated tests in:
  - `crates/franken-node/src/control_plane/control_epoch.rs`
  - `crates/franken-node/src/connector/artifact_persistence.rs`
  - `tests/security/future_epoch_rejection.rs`
  - `tests/integration/artifact_replay_hooks.rs`

## Validation Commands (via rch)

- PASS: `cargo test ... artifact_persistence` (19 passed)
- PASS: `cargo test ... validity_window` (7 passed)
- PASS: `cargo test ... event_contains_required_context` (2 passed)
- PASS (warnings): `cargo check --all-targets`
- FAIL (pre-existing): `cargo clippy --all-targets -- -D warnings`
- FAIL (pre-existing): `cargo fmt --check`

## Environment Notes

`rch` remote sync currently fails due permission-denied on `/data/projects/remote_compilation_helper/perf.data` and falls back to local execution. This affected all `rch exec` commands but did not block targeted test/check execution.
